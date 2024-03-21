// Command edgedict-fetch downloads and extracts MS Edge dictionaries.
package main

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
)

var (
	Output     = pflag.StringP("output", "o", ".", "Output directory")
	Filter     = pflag.StringSliceP("filter", "f", nil, "Filter downloaded dictionaries (e.g., en-us, en-gb)")
	NoOptimize = pflag.BoolP("no-optimize", "x", false, "Do not attempt to optimize download")
	Help       = pflag.BoolP("help", "h", false, "Show this help text")
)

func main() {
	pflag.Parse()

	if pflag.NArg() > 1 || *Help {
		fmt.Printf("Usage: %s [options] [appxbundle]\n\nOptions:\n%s\nIf appxbundle is not specified, the latest version of Microsoft.ImmersiveReader\nwill be downloaded.\n", os.Args[0], pflag.CommandLine.FlagUsages())
		if !*Help {
			os.Exit(2)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := run(ctx, pflag.Arg(0)); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, pkg string) error {
	if len(*Filter) != 0 {
		for i, f := range *Filter {
			f = strings.TrimSpace(f)
			f = strings.ReplaceAll(f, "-", "_")
			if !strings.HasPrefix(f, "Dictionary_") {
				f = "Dictionary_" + strings.ToUpper(strings.TrimSuffix(f, ".db")) + ".db"
			}
			(*Filter)[i] = f
		}
		slices.Sort(*Filter)
		*Filter = slices.Compact(*Filter)
	}

	if err := os.Mkdir(*Output, 0777); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}

	if pkg == "" {
		if url, err := packageURL(ctx); err != nil {
			return fmt.Errorf("get package url: %w", err)
		} else if err := download(ctx, *Output, url, !*NoOptimize, *Filter...); err != nil {
			return fmt.Errorf("download: %w", err)
		}
		return nil
	}

	if u, err := url.Parse(pkg); err == nil && u.Scheme == "http" || u.Scheme == "https" {
		if err := download(ctx, *Output, pkg, !*NoOptimize, *Filter...); err != nil {
			return fmt.Errorf("download: %w", err)
		}
		return nil
	}

	fmt.Printf("info: opening package %s\n", pkg)
	bnd, err := zip.OpenReader(pkg)
	if err != nil {
		return fmt.Errorf("process appx bundle: %w", err)
	}
	defer bnd.Close()

	if err := extract(ctx, &bnd.Reader, *Output, *Filter...); err != nil {
		return fmt.Errorf("process appx bundle: %w", err)
	}
	return nil
}

func packageURL(ctx context.Context) (string, error) {
	fmt.Printf("info: getting package url from wsus\n")
	if u, err := packageWSUS(ctx); err == nil {
		return u, nil
	} else {
		fmt.Fprintf(os.Stderr, "warn: failed to get package url from wsus (error: %v)\n", err)
	}

	fmt.Printf("info: getting package url from rg-adguard\n")
	if u, err := packageRg(ctx); err == nil {
		return u, nil
	} else {
		fmt.Fprintf(os.Stderr, "warn: failed to get package url from rg-adguard (error: %v)\n", err)
	}

	fmt.Printf("info: getting package url from internet archive\n")
	if u, err := packageIA(ctx); err == nil {
		return u, nil
	} else {
		fmt.Fprintf(os.Stderr, "warn: failed to get package url from internet archive (error: %v)\n", err)
	}

	return "", fmt.Errorf("all sources failed")
}

func download(ctx context.Context, dir, url string, optimize bool, filter ...string) error {
	// disable optimization if not all filtered packages are known or if no filters are provided
	if len(filter) != 0 {
		for _, f := range filter {
			if _, ok := pkg_Index[f]; !ok {
				optimize = false
			}
		}
	} else {
		optimize = false
	}

	// create the request
	baseReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	baseReq.Header.Set("User-Agent", "Microsoft-Delivery-Optimization/10.1")
	fmt.Printf("info: using package url %s\n", url)

	// attempt to download with optimization
	if optimize {
		for _, name := range filter {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			rng := pkg_Index[name]
			err, retry := func() (error, bool) {
				tf, err := os.CreateTemp(dir, "."+name+".")
				if err != nil {
					return fmt.Errorf("create output file: %w", err), false
				}
				defer os.Remove(tf.Name())
				defer tf.Close()

				req := baseReq.Clone(ctx)
				req.Header.Set("Range", "bytes="+strconv.FormatInt(rng.Offset, 10)+"-"+strconv.FormatInt(rng.Offset+rng.Compressed-1, 10))
				fmt.Printf("info: downloading size=%d %s\n", rng.Compressed, req.Header.Get("Range"))

				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					return err, false
				}
				if resp.StatusCode != http.StatusPartialContent {
					if resp.StatusCode == http.StatusOK {
						return fmt.Errorf("range requests not supported by server"), true
					}
					return fmt.Errorf("response status %d (%s)", resp.StatusCode, resp.Status), true
				}
				defer resp.Body.Close()

				if v, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64); err == nil && v != 0 {
					if rng.Compressed != v {
						return fmt.Errorf("incorrect response length (expected %d, got %d)", rng.Compressed, v), true
					}
				}

				var reader io.Reader
				switch rng.Method {
				case zip.Store:
					reader = resp.Body
				case zip.Deflate:
					fr := flate.NewReader(resp.Body)
					defer fr.Close()
					reader = fr
				}

				ss := crc32.NewIEEE()
				if n, err := io.Copy(io.MultiWriter(ss, tf), reader); err != nil {
					return fmt.Errorf("download response: %w", err), false
				} else if rng.Uncompressed != int64(n) {
					return fmt.Errorf("incorrect uncompressed response length (expected %d, got %d)", rng.Uncompressed, n), false
				} else if v := ss.Sum32(); rng.CRC32 != v {
					return fmt.Errorf("incorrect uncompressed response crc32 (expected %08x, got %08x)", rng.CRC32, v), false
				}

				if err := tf.Sync(); err != nil {
					return fmt.Errorf("download response: %w", err), false
				} else if err := tf.Close(); err != nil {
					return fmt.Errorf("download response: %w", err), false
				} else if err := os.Rename(tf.Name(), filepath.Join(dir, name)); err != nil {
					return fmt.Errorf("download response: %w", err), false
				}

				fmt.Printf("info: downloaded %s size=%d crc32=%08x\n", name, rng.Uncompressed, rng.CRC32)
				return nil, false
			}()
			if retry {
				// ranges not supported
				fmt.Fprintf(os.Stderr, "warn: failed to download with optimization (error: %v), trying full download\n", err)
				optimize = false
				break
			}
			if err != nil {
				return err
			}
		}
	}

	// attempt to download normally
	if !optimize {
		tf, err := os.CreateTemp(dir, ".appx.")
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer os.Remove(tf.Name())
		defer tf.Close()

		req := baseReq.Clone(ctx)
		fmt.Printf("info: downloading size=%d\n", pkg_Size)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("response status %d (%s)", resp.StatusCode, resp.Status)
		}
		defer resp.Body.Close()

		ss := sha1.New()
		if n, err := io.Copy(io.MultiWriter(ss, tf), resp.Body); err != nil {
			return fmt.Errorf("download response: %w", err)
		} else if pkg_Size != int64(n) {
			return fmt.Errorf("incorrect response length (expected %d, got %d)", pkg_Size, n)
		} else if v := hex.EncodeToString(ss.Sum(nil)); pkg_DigestSHA1 != v {
			return fmt.Errorf("incorrect response sha1 (expected %s, got %s)", pkg_DigestSHA1, v)
		}

		respFilename := path.Base(resp.Request.URL.Path)
		if _, p, _ := mime.ParseMediaType(resp.Header.Get("Content-Disposition")); p != nil {
			if v, ok := p["filename"]; ok {
				respFilename = v
			}
		}
		fmt.Printf("info: downloaded %s size=%d sha1=%s\n", respFilename, pkg_Size, pkg_DigestSHA1)

		bnd, err := zip.NewReader(tf, pkg_Size)
		if err != nil {
			return fmt.Errorf("process appx bundle: %w", err)
		}
		if err := extract(ctx, bnd, dir, filter...); err != nil {
			return fmt.Errorf("process appx bundle: %w", err)
		}
	}

	// done
	return nil
}

func extract(ctx context.Context, bnd *zip.Reader, dir string, filter ...string) error {
	var need map[string]struct{}
	if len(filter) != 0 {
		need = map[string]struct{}{}
		for _, f := range filter {
			need[f] = struct{}{}
		}
	}
	for _, f := range bnd.File {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if strings.HasSuffix(f.Name, ".appx") && !strings.HasSuffix(f.Name, "_x86.appx") {
			buf, err := fs.ReadFile(bnd, f.Name)
			if err != nil {
				return fmt.Errorf("read package from bundle: %w", err)
			}

			pkg, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
			if err != nil {
				return fmt.Errorf("read package from bundle: %w", err)
			}

			for _, x := range pkg.File {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}
				name := path.Base(x.Name)
				if strings.HasPrefix(name, "Dictionary_") && strings.HasSuffix(name, ".db") {
					if os.Getenv("EDGEDICT_OFFSETS") == "1" {
						if f.Method != zip.Store {
							panic("appx in bundle is compressed")
						}

						off1, _ := f.DataOffset()
						off2, _ := x.DataOffset()

						zf, _ := x.Open()
						buf, _ := io.ReadAll(zf)
						zf.Close()

						fmt.Printf("\t%q: {0x%08x, %d, %d, %d, %d,}, // %s // %s\n", name, crc32.ChecksumIEEE(buf), x.Method, off1+off2, int64(x.CompressedSize64), int64(x.UncompressedSize64), f.Name, x.Name)
						continue
					}
					if need != nil {
						if _, ok := need[name]; !ok {
							continue
						}
						delete(need, name)
					}
					if err := func() error {
						tf, err := os.CreateTemp(dir, "."+name+".")
						if err != nil {
							return fmt.Errorf("create output file: %w", err)
						}
						defer os.Remove(tf.Name())
						defer tf.Close()

						pf, err := pkg.Open(x.Name)
						if err != nil {
							return err
						}
						defer pf.Close()

						if _, err := io.Copy(tf, pf); err != nil {
							return err
						}

						if err := tf.Sync(); err != nil {
							return err
						} else if err := tf.Close(); err != nil {
							return err
						} else if err := os.Rename(tf.Name(), filepath.Join(dir, name)); err != nil {
							return err
						}
						return nil
					}(); err != nil {
						return fmt.Errorf("read package from bundle: extract %s: %w", name, err)
					}
					fmt.Printf("info: extracted %s size=%d\n", name, x.UncompressedSize64)
				}
			}
		}
	}
	for name := range need {
		return fmt.Errorf("missing %s", name)
	}
	return nil
}
