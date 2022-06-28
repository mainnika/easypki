// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Command easypki provides a simple client to manage a local PKI.
package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/mainnika/easypki/pkg/certificate"
	"github.com/mainnika/easypki/pkg/easypki"
	"github.com/mainnika/easypki/pkg/store"
	"github.com/urfave/cli/v2"
)

const (
	defaultCAName = "ca"
)

type router struct {
	PKI *easypki.EasyPKI
}

func (r *router) create(c *cli.Context) error {
	if !c.Args().Present() {
		cli.ShowSubcommandHelp(c)
		return fmt.Errorf("usage: %v name (common name defaults to name, use --cn and "+
			"different name if you need multiple certs for same cn)", c.Command.FullName())
	}

	commonName := strings.Join(c.Args().Slice(), " ")
	var filename string
	if filename = c.String("filename"); len(filename) == 0 {
		filename = strings.Replace(commonName, " ", "_", -1)
		filename = strings.Replace(filename, "*", "wildcard", -1)
	}

	subject := pkix.Name{CommonName: commonName}
	if str := c.String("organization"); str != "" {
		subject.Organization = []string{str}
	}
	if str := c.String("locality"); str != "" {
		subject.Locality = []string{str}
	}
	if str := c.String("country"); str != "" {
		subject.Country = []string{str}
	}
	if str := c.String("province"); str != "" {
		subject.Province = []string{str}
	}
	if str := c.String("organizational-unit"); str != "" {
		subject.OrganizationalUnit = []string{str}
	}

	template := &x509.Certificate{
		Subject:    subject,
		NotAfter:   time.Now().AddDate(0, 0, c.Int("expire")),
		MaxPathLen: c.Int("max-path-len"),
	}

	var signer *certificate.Bundle
	isRootCa := c.Bool("ca")
	if !isRootCa {
		var err error
		signer, err = r.PKI.GetCA(c.String("ca-name"))
		if err != nil {
			return err
		}
	}

	isIntCA := c.Bool("intermediate")
	if isIntCA || isRootCa {
		template.IsCA = true
	} else if c.Bool("client") {
		template.EmailAddresses = c.StringSlice("email")
	} else {
		// We default to server
		IPs := make([]net.IP, 0, len(c.StringSlice("ip")))
		for _, ipStr := range c.StringSlice("ip") {
			if i := net.ParseIP(ipStr); i != nil {
				IPs = append(IPs, i)
			}
		}
		template.IPAddresses = IPs
		template.DNSNames = c.StringSlice("dns")
	}

	req := &easypki.Request{
		Name:                filename,
		Template:            template,
		IsClientCertificate: c.Bool("client"),
		PrivateKeySize:      c.Int("private-key-size"),
	}
	if err := r.PKI.Sign(signer, req); err != nil {
		return err
	}

	return nil
}

func (r *router) revoke(c *cli.Context) error {
	if !c.Args().Present() {
		cli.ShowSubcommandHelp(c)
		return fmt.Errorf("usage: %v path/to/cert.crt", c.Command.FullName())
	}

	for _, p := range c.Args().Slice() {
		name := strings.TrimSuffix(path.Base(p), ".crt")
		ca := path.Base(strings.TrimSuffix(path.Dir(p), store.LocalCertsDir))
		bundle, err := r.PKI.GetBundle(ca, name)
		if err != nil {
			return fmt.Errorf("failed fetching certificate %v under CA %v: %v", name, ca, err)
		}
		err = r.PKI.Revoke(ca, bundle.Cert)
		if err != nil {
			return fmt.Errorf("failed revoking certificate %v under CA %v: %v", name, ca, err)
		}
	}

	return nil
}

func (r *router) crl(c *cli.Context) error {
	ca := c.String("ca-name")
	crl, err := r.PKI.CRL(ca, time.Now().AddDate(0, 0, c.Int("expire")))
	if err != nil {
		return fmt.Errorf("failed generating CRL for CA %v: %v", ca, err)
	}
	err = pem.Encode(os.Stdout, &pem.Block{
		Type:  "X509 CRL",
		Bytes: crl,
	})
	if err != nil {
		return fmt.Errorf("failed writing PEM formated CRL to stdout: %v", err)
	}

	return nil
}

func (r *router) run() {
	app := cli.NewApp()
	app.Name = "easypki"
	app.Usage = "Manage pki"
	app.Authors = []*cli.Author{{Name: "Jeremy Clerc", Email: "jeremy@clerc.io"}}
	app.Version = "1.0.0"

	caNameFlag := cli.StringFlag{
		Name:  "ca-name",
		Usage: "Specify a different CA name to use an intermediate CA.",
		Value: defaultCAName,
	}

	local := r.PKI.Store.(*store.Local)
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:        "root",
			Value:       filepath.Join(os.Getenv("PWD"), "pki_auto_generated_dir"),
			Usage:       "path to pki root directory",
			EnvVars:     []string{"PKI_ROOT"},
			Destination: &local.Root,
		},
	}
	app.Commands = []*cli.Command{
		{
			Name:        "revoke",
			Usage:       "revoke path/to/ca-name/certs/cert path/to/ca-name/certs/cert2",
			Description: "Revoke the given certificates",
			Action:      r.revoke,
		},
		{
			Name:        "crl",
			Description: "generate certificate revocation list",
			Action:      r.crl,
			Flags: []cli.Flag{
				&cli.IntFlag{
					Name:  "expire",
					Usage: "expiration limit in days",
					Value: 7,
				},
				&caNameFlag,
			},
		},
		{
			Name:        "create",
			Usage:       "create COMMON NAME",
			Description: "create private key + cert signed by CA",
			Action:      r.create,
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "ca",
					Usage: "certificate authority",
				},
				&cli.BoolFlag{
					Name:  "intermediate",
					Usage: "intermediate certificate authority; implies --ca",
				},
				&caNameFlag,
				&cli.IntFlag{
					Name:  "max-path-len",
					Usage: "intermediate maximum path length",
					Value: -1, // default to less-than 0 when not defined
				},
				&cli.BoolFlag{
					Name:  "client",
					Usage: "generate a client certificate (default is server)",
				},
				&cli.IntFlag{
					Name:  "expire",
					Usage: "expiration limit in days",
					Value: 365,
				},
				&cli.IntFlag{
					Name:  "private-key-size",
					Usage: "size of the private key (default: 2048)",
					Value: 2048,
				},
				&cli.StringFlag{
					Name:  "filename",
					Usage: "filename for bundle, use when you generate multiple certs for same cn",
				},
				&cli.StringFlag{
					Name:    "organization",
					EnvVars: []string{"PKI_ORGANIZATION"},
				},
				&cli.StringFlag{
					Name:    "organizational-unit",
					EnvVars: []string{"PKI_ORGANIZATIONAL_UNIT"},
				},
				&cli.StringFlag{
					Name:    "locality",
					EnvVars: []string{"PKI_LOCALITY"},
				},
				&cli.StringFlag{
					Name:    "country",
					EnvVars: []string{"PKI_COUNTRY"},
					Usage:   "Country name, 2 letter code",
				},
				&cli.StringFlag{
					Name:    "province",
					Usage:   "province/state",
					EnvVars: []string{"PKI_PROVINCE"},
				},
				&cli.StringSliceFlag{
					Name:    "dns",
					Aliases: []string{"d"},
					Usage:   "dns alt names",
				},
				&cli.StringSliceFlag{
					Name:    "ip",
					Aliases: []string{"i"},
					Usage:   "IP alt names",
				},
				&cli.StringSliceFlag{
					Name:    "email",
					Aliases: []string{"e"},
					Usage:   "Email alt names",
				},
			},
		},
	}

	app.Run(os.Args)
}

func main() {
	r := router{PKI: &easypki.EasyPKI{Store: &store.Local{}}}
	r.run()
}
