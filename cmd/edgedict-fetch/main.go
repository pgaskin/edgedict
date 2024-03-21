// Command edgedict-fetch downloads and extracts MS Edge dictionaries.
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"

	"github.com/spf13/pflag"
)

var (
	Output = pflag.StringP("output", "o", ".", "Output directory")
	Help   = pflag.BoolP("help", "h", false, "Show this help text")
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
	var err error
	var bnd *zip.ReadCloser
	if pkg != "" {
		fmt.Printf("info: opening package %q\n", pkg)
		bnd, err = zip.OpenReader(pkg)
	} else {
		fmt.Printf("info: getting package url\n")
		u, err1 := packageWSUS(ctx)
		if err1 != nil {
			fmt.Fprintf(os.Stderr, "warn: failed to get package url from wsus (error: %v), trying rg-adguard\n", err1)
			u, err1 = packageRg(ctx)
		}
		if err1 != nil {
			return fmt.Errorf("get package url: %w", err1)
		}

		fmt.Printf("info: downloading %q\n", u)
		fn, err1 := download(ctx, u)
		if err1 != nil {
			return fmt.Errorf("download package: %w", err1)
		}
		defer os.Remove(fn)

		bnd, err = zip.OpenReader(fn)
	}
	if err != nil {
		return fmt.Errorf("open package: %w", err)
	}
	defer bnd.Close()

	fmt.Printf("info: extracting dictionaries from package\n")
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
				if m, _ := path.Match("Dictionary_*.db", path.Base(x.Name)); m {
					fmt.Printf("info: extracting %s from %s\n", x.Name, f.Name)
					if err := extract(pkg, x.Name, *Output); err != nil {
						return fmt.Errorf("extract dictionary from package: %w", err)
					}
					_ = os.Chmod(x.Name, 0444)
				}
			}
		}
	}
	return nil
}

func download(ctx context.Context, url string) (string, error) {
	tf, err := os.CreateTemp("", "appx.")
	if err != nil {
		return "", err
	}
	defer tf.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		os.Remove(tf.Name())
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		os.Remove(tf.Name())
		return "", err
	}
	defer resp.Body.Close()

	if _, err := io.Copy(tf, resp.Body); err != nil {
		os.Remove(tf.Name())
		return "", err
	}
	if err := tf.Close(); err != nil {
		os.Remove(tf.Name())
		return "", err
	}
	return tf.Name(), nil
}

func extract(z *zip.Reader, name, dir string) error {
	if err := os.Mkdir(dir, 0777); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}

	tf, err := os.CreateTemp(dir, path.Base(name)+".")
	if err != nil {
		return err
	}
	defer tf.Close()
	defer os.Remove(tf.Name())

	fi, err := z.Open(name)
	if err != nil {
		return err
	}
	defer fi.Close()

	if _, err := io.Copy(tf, fi); err != nil {
		return err
	}
	_ = tf.Chmod(0444)

	if err := tf.Close(); err != nil {
		return err
	}
	return os.Rename(tf.Name(), filepath.Join(dir, path.Base(name)))
}
