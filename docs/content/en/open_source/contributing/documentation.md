---
title: "Amend Documentation"
description: "How to amend the documentation"
draft: false
weight: 2
---

The documentation is built with [Hugo](https://gohugo.io/) and uses the theme [Docsy](https://www.docsy.dev).
Static files for the webside are build with github actions and are publish in the gh-pages branch.

## How to run a local preview

1. [Install Hugo](https://gohugo.io/getting-started/installing/). Make sure you have installed the extended version with Sass/SCSS support. Please note there are various Linux packages available on [Hugo GitHub](https://github.com/gohugoio/hugo/releases)

2. Install JavaScript packages

    To build or update your site's CSS resources, you also need PostCSS to create the final assets. If you need to install it, you must have a recent version of NodeJS installed on your machine so you can use npm, the Node package manager. By default, npm installs tools under the directory where you run npm install:

    {{< highlight bash >}}
    cd docs
    npm install
    {{< /highlight >}}

3. Clone the DefectDojo git repository with the option `--recurse-submodules`. If you have already cloned the repository, make sure that you have checked out out the Docsy theme or use `git submodule` to check it out:

    {{< highlight bash >}}
    cd docs/themes/docsy
    git submodule update --init --recursive
    {{< /highlight >}}

4. Switch to the docs folder and start the hugo server with hot reloading `hugo server -D --config config.dev.toml`
5. Visit [http://localhost:1313/django-DefectDojo/dev](http://localhost:1313/django-DefectDojo/dev).

See also the [Docsy installation procedures](https://www.docsy.dev/docs/getting-started/) for reference.
