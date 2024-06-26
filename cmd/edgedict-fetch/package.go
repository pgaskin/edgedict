package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/pgaskin/xmlwriter"
)

// WSUS namespaces.
const (
	ns_SoapEnvelope xmlwriter.NS = "http://www.w3.org/2003/05/soap-envelope"
	ns_Addressing   xmlwriter.NS = "http://www.w3.org/2005/08/addressing"
	ns_WSSSecExt    xmlwriter.NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	ns_WSSUtility   xmlwriter.NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	ns_MSUS_WUA     xmlwriter.NS = "http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization"
	ns_CWS          xmlwriter.NS = "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService"
)

// Windows Update client information.
const (
	wu_Locale         = "en-US"
	wu_FlightRing     = "RP"
	wu_DeviceFamily   = "Windows.Desktop"
	wu_OSVersion      = "10.0.19041.2546" // 22H2
	wu_OSArchitecture = "AMD64"
)

// WSUS client web service information.
const (
	cws_URL      = "https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx"
	cws_Protocol = "1.81"
)

// Immersive Reader package information.
const (
	pkg_PackageIdentityName = "Microsoft.ImmersiveReader"
	pkg_PublisherId         = "8wekyb3d8bbwe"
	pkg_PackageFamilyName   = pkg_PackageIdentityName + "_" + pkg_PublisherId

	// ms-windows-store:PDP?PFN=Microsoft.ImmersiveReader_8wekyb3d8bbwe
	pkg_ProductId = "9pjzqz821dq2"

	// https://storeedgefd.dsx.mp.microsoft.com/v9.0/products/9pjzqz821dq2?market=US&locale=en-us&deviceFamily=Windows.Desktop
	pkg_WuCategoryId = "f8cacb57-c61c-42ad-ac71-dc412e230bde"

	// https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/SyncUpdates FilterAppCategoryIds>CategoryIdentifier>Id{f8cacb57-c61c-42ad-ac71-dc412e230bde}
	pkg_FileName       = "71a7807e-88e0-45e8-8ddc-21fd62410f83.appxbundle"
	pkg_UpdateId       = "b49ac25b-ccc7-44c5-a4ab-d8deaed4d6a1"
	pkg_RevisionNumber = "1"
	pkg_DigestSHA1     = "4b1cecf7ff096b39874481095d88012b098d1f19"
	pkg_Size           = 444614378
)

// Zip offsets for 4b1cecf7ff096b39874481095d88012b098d1f19.
//
// This works because the appx files inside the bundle are not compressed.
var pkg_Index = map[string]struct {
	CRC32        uint32
	Method       uint16
	Offset       int64
	Compressed   int64
	Uncompressed int64
}{
	"Dictionary_DE.db":    {0x0cbd8733, 8, 37631947, 3978399, 4829184},    // ImmersiveReader.Apps.Uwp_1.4.0.0_language-de.appx // DictionaryData/de/Dictionary_DE.db
	"Dictionary_ES.db":    {0xe93c4b02, 8, 52447770, 8588608, 9748480},    // ImmersiveReader.Apps.Uwp_1.4.0.0_language-es.appx // DictionaryData/es/Dictionary_ES.db
	"Dictionary_FR.db":    {0xdf89c23d, 8, 137363318, 2725609, 3239936},   // ImmersiveReader.Apps.Uwp_1.4.0.0_language-fr.appx // DictionaryData/fr/Dictionary_FR.db
	"Dictionary_IT.db":    {0xa5b9613c, 8, 145666864, 14609764, 16494592}, // ImmersiveReader.Apps.Uwp_1.4.0.0_language-it.appx // DictionaryData/it/Dictionary_IT.db
	"Dictionary_EN_GB.db": {0x282c1e3b, 8, 245799764, 25755939, 30228480}, // ImmersiveReader.Apps.Uwp_1.4.0.0_x64.appx // DictionaryData/en/Dictionary_EN_GB.db
	"Dictionary_EN_US.db": {0x00951d02, 8, 271555794, 24495368, 28549120}, // ImmersiveReader.Apps.Uwp_1.4.0.0_x64.appx // DictionaryData/en/Dictionary_EN_US.db
}

// packageRg gets the package URL from the store.rg-adguard.net API.
func packageRg(ctx context.Context) (string, error) {
	data := url.Values{
		"type": {"CategoryID"},
		"url":  {pkg_WuCategoryId},
		"ring": {wu_FlightRing},
		"lang": {wu_Locale},
	}.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://store.rg-adguard.net/api/GetFiles", strings.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len(data)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make request to rg-adguard store api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("rg-adguard api response status %d (%s)", resp.StatusCode, resp.Status)
	}

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	m := regexp.MustCompile(`(?i)<a[^>]*\shref="([^"]+)"[^>]*>\s*` + regexp.QuoteMeta(pkg_PackageIdentityName) + `_.+?_` + regexp.QuoteMeta(pkg_PublisherId) + `\.appxbundle\s*</a>`).FindStringSubmatch(string(buf))
	if m == nil {
		return "", fmt.Errorf("couldn't find matching appxbundle for package")
	}
	return html.UnescapeString(m[1]), nil
}

// packageWSUS gets the package URL from the WSUS API.
func packageWSUS(ctx context.Context) (string, error) {
	// see https://github.com/littlebyteorg/appledb/blob/06ade711920f04afee900cb54ad7b7afa6f09316/tasks/grab_windows_store.py
	// see https://github.com/LSPosed/MagiskOnWSALocal/blob/main/scripts/generateWSALinks.py
	// see https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/2f66a682-164f-47ec-968e-e43c0a85dc21

	sbuf, err := hex.DecodeString(pkg_DigestSHA1)
	if err != nil {
		return "", fmt.Errorf("failed to convert expected package sha1 to base64: decode hex: %w", err)
	}
	digest := base64.StdEncoding.EncodeToString(sbuf)

	var locations struct {
		Updates struct {
			FileLocations []struct {
				FileDigest string `xml:"FileDigest"`
				URL        string `xml:"Url"`
			} `xml:"FileLocations>FileLocation"`
		} `xml:"Body>GetExtendedUpdateInfo2Response>GetExtendedUpdateInfo2Result"`
	}
	if err := cws(ctx, "GetExtendedUpdateInfo2", func(x *xmlwriter.XMLWriter) error {
		{
			x.Start(ns_CWS, "updateIDs")
			x.Start(ns_CWS, "UpdateIdentity")
			x.Start(ns_CWS, "UpdateID")
			x.Text(false, pkg_UpdateId)
			x.EndAuto()
			x.Start(ns_CWS, "RevisionNumber")
			x.Text(false, "1")
			x.EndAuto()
			x.EndAuto()
			x.EndAuto()
		}
		{
			x.Start(ns_CWS, "infoTypes")
			for _, t := range []string{"FileUrl"} {
				x.Start(ns_CWS, "XmlUpdateFragmentType")
				x.Text(false, t)
				x.EndAuto()
			}
			x.EndAuto()
		}
		return nil
	}, &locations); err != nil {
		return "", fmt.Errorf("failed to call wsus cws: GetExtendedUpdateInfo2: %w", err)
	}
	for _, f := range locations.Updates.FileLocations {
		if f.FileDigest == digest {
			return f.URL, nil
		}
	}
	return "", fmt.Errorf("failed to find link with digest %s from wsus (got %v)", digest, locations.Updates.FileLocations)
}

func cws(ctx context.Context, action string, body func(x *xmlwriter.XMLWriter) error, out any) error {
	var soap bytes.Buffer
	x := xmlwriter.New(&soap)

	x.Indent("    ")
	x.Start(ns_SoapEnvelope, "Envelope", ns_SoapEnvelope.Bind("s"), ns_Addressing.Bind("a"), ns_WSSUtility.Bind("u"))
	{
		x.Start(ns_SoapEnvelope, "Header")
		{
			x.Start(ns_Addressing, "Action")
			x.Attr(ns_SoapEnvelope, "mustUnderstand", "1")
			x.Text(false, string(ns_CWS+"/"+xmlwriter.NS(action)))
			x.EndAuto()
		}
		{
			x.Start(ns_Addressing, "MessageID")
			x.Text(false, uuid4())
			x.EndAuto()
		}
		{
			x.Start(ns_Addressing, "To")
			x.Text(false, cws_URL)
			x.EndAuto()
		}
		{
			x.Start(ns_WSSSecExt, "Security", ns_WSSSecExt.Bind("o"))
			x.Attr(ns_SoapEnvelope, "mustUnderstand", "1")
			{
				x.Start(ns_WSSUtility, "Timestamp")
				x.Start(ns_WSSUtility, "Created")
				x.Text(false, "2020-01-01T00:00:00.000Z")
				x.EndAuto()
				x.Start(ns_WSSUtility, "Expires")
				x.Text(false, "2050-01-01T00:00:00.000Z")
				x.EndAuto()
				x.EndAuto()
			}
			{
				x.Start(ns_MSUS_WUA, "WindowsUpdateTicketsToken", ns_MSUS_WUA.Bind("t"))
				x.Attr(ns_WSSUtility, "id", "ClientMSA")
				x.Start(ns_MSUS_WUA, "TicketType")
				x.Attr(ns_MSUS_WUA, "Name", "AAD")
				x.Attr(ns_MSUS_WUA, "Version", "1.0")
				x.Attr(ns_MSUS_WUA, "Policy", "MBI_SSL")
				x.EndAuto()
				x.EndAuto()
			}
			x.EndAuto()
		}
		x.EndAuto()
	}
	{
		x.Start(ns_SoapEnvelope, "Body")
		{
			x.Start(ns_CWS, action, ns_CWS.Bind(""))
			{
				x.Start(ns_CWS, "protocolVersion")
				x.Text(false, cws_Protocol)
				x.EndAuto()
			}
			if body != nil {
				if err := body(x); err != nil {
					return err
				}
			}
			x.EndAuto()
		}
		x.EndAuto()
	}
	x.EndAuto()

	if err := x.Close(); err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cws_URL, &soap)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
	req.Header.Set("User-Agent", "Windows-Update-Agent/"+wu_OSVersion+" Client-Protocol/"+cws_Protocol)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http response status %d (%s)", resp.StatusCode, resp.Status)
	}

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return xml.Unmarshal(buf, out)
}

func uuid4() string {
	var u [16]byte
	if _, err := io.ReadFull(rand.Reader, u[:]); err != nil {
		panic(fmt.Errorf("uuid: %w", err))
	}
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:])
}

func packageIA(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://archive.org/wayback/available?url=http://tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/"+strings.TrimSuffix(pkg_FileName, path.Ext(pkg_FileName))+"?*", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make request to internet archive api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("internet archive response status %d (%s)", resp.StatusCode, resp.Status)
	}

	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "application/json" {
		return "", fmt.Errorf("internet archive returned non-json response (got %q)", mt)
	}

	var obj struct {
		URL               string `json:"url"`
		ArchivedSnapshots struct {
			Closest struct {
				Status    string `json:"status"`
				Available bool   `json:"available"`
				URL       string `json:"url"`
				Timestamp string `json:"timestamp"`
			} `json:"closest"`
		} `json:"archived_snapshots"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		return "", fmt.Errorf("failed to parse internet archive response: %w", err)
	}
	if !obj.ArchivedSnapshots.Closest.Available {
		return "", fmt.Errorf("no snapshots available")
	}
	if obj.ArchivedSnapshots.Closest.Status != "200" {
		return "", fmt.Errorf("latest snapshot was not successful")
	}
	if obj.ArchivedSnapshots.Closest.URL == "" {
		return "", fmt.Errorf("latest snapshot does not have a url")
	}

	// make the link direct
	u, err := url.Parse(obj.ArchivedSnapshots.Closest.URL)
	if err != nil {
		return "", fmt.Errorf("failed to parse snapshot url %q: %w", obj.ArchivedSnapshots.Closest.URL, err)
	}
	if spl := strings.Split(u.Path, "/"); len(spl) < 3 || spl[0] != "" || spl[1] != "web" || strings.HasSuffix(spl[2], "_") {
		return "", fmt.Errorf("failed to parse snapshot url %q: does not match expected format", obj.ArchivedSnapshots.Closest.URL)
	} else {
		spl[2] += "im_"
		u.Path = strings.Join(spl, "/")
	}
	return u.String(), nil
}
