package imports

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/isthobbit/vigyl/internal/globs"
)

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

func TestParseJS(t *testing.T) {
	src := `
import express from "express";
import { merge } from 'lodash/merge';
import * as z from "@scope/pkg/sub";
import "side-effect";
export { x } from "re-export";
const a = require("axios");
const lazy = await import("chalk");
import local from "./local";
import fs from "node:fs";

// import fake from "commented-out";
/* const b = require("block-comment"); */
const s = "require('in-a-string')";
const t = 'import x from "also-a-string"';
obj.require("method-call");
`
	got := sorted(parseJS(src))
	want := sorted([]string{
		"express", "lodash/merge", "@scope/pkg/sub", "side-effect", "re-export",
		"axios", "chalk", "./local", "node:fs",
	})
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseJS:\n got  %v\n want %v", got, want)
	}
}

func TestJSPackage(t *testing.T) {
	cases := map[string]string{
		"lodash":         "lodash",
		"lodash/merge":   "lodash",
		"@scope/pkg":     "@scope/pkg",
		"@scope/pkg/sub": "@scope/pkg",
		"./local":        "",
		"../up":          "",
		"node:fs":        "",
		"/abs":           "",
	}
	for in, want := range cases {
		if got := jsPackage(in); got != want {
			t.Errorf("jsPackage(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParsePython(t *testing.T) {
	src := `"""Module docstring.

import not_real
"""
import os, sys as system
import requests
from flask import Flask
from yaml.loader import SafeLoader
from . import sibling
from .pkg import thing
import jwt  # comment
# import commented
x = "import in_string"
`
	got := sorted(parsePython(src))
	want := sorted([]string{"os", "sys", "requests", "flask", "yaml.loader", "jwt"})
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parsePython:\n got  %v\n want %v", got, want)
	}
}

func TestParseGo(t *testing.T) {
	src := []byte(`package main

import (
	"fmt"
	yaml "gopkg.in/yaml.v3"
	"github.com/foo/bar/sub"
)

var s = "github.com/not/an/import"
`)
	got := sorted(parseGo(src))
	want := sorted([]string{"fmt", "gopkg.in/yaml.v3", "github.com/foo/bar/sub"})
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseGo:\n got  %v\n want %v", got, want)
	}
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestImporters(t *testing.T) {
	root := t.TempDir()
	// A monorepo: two Python services and a JS frontend.
	write(t, root, "api/app/db.py", "import requests\nimport yaml\n")
	write(t, root, "api/app/util.py", "import os\n")
	write(t, root, "worker/main.py", "import requests\n")
	write(t, root, "web/src/index.ts", "import _ from 'lodash';\n")
	write(t, root, "web/node_modules/lodash/x.js", "require('lodash')\n") // dependency code: skipped
	write(t, root, "api/tests/test_db.py", "import requests\n")           // excluded below
	write(t, root, "cmd/tool/main.go", "package main\nimport \"github.com/foo/bar/sub\"\n")

	ix, err := Build(root, globs.Compile([]string{"**/tests/**"}))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, eco, pkg, manifest string
		known                    bool
		files                    []string
	}{
		{"scoped to its manifest", "PyPI", "requests", "api/requirements.txt", true, []string{"api/app/db.py"}},
		{"root manifest sees all", "PyPI", "requests", "requirements.txt", true, []string{"api/app/db.py", "worker/main.py"}},
		{"python alias", "PyPI", "PyYAML", "api/requirements.txt", true, []string{"api/app/db.py"}},
		{"not imported", "PyPI", "django", "api/requirements.txt", true, nil},
		{"npm, node_modules skipped", "npm", "lodash", "web/package-lock.json", true, []string{"web/src/index.ts"}},
		{"yarn counts as npm", "yarn", "lodash", "web/yarn.lock", true, []string{"web/src/index.ts"}},
		{"go module prefix", "Go", "github.com/foo/bar", "go.mod", true, []string{"cmd/tool/main.go"}},
		{"go stdlib is unknown", "Go", "stdlib", "go.mod", false, nil},
		{"unsupported ecosystem", "Maven", "org.apache:commons", "pom.xml", false, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u := ix.Importers(c.eco, c.pkg, c.manifest)
			if u.Known != c.known || !reflect.DeepEqual(u.Files, c.files) {
				t.Errorf("got known=%v files=%v, want known=%v files=%v", u.Known, u.Files, c.known, c.files)
			}
		})
	}
}
