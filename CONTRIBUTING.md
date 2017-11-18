# Contributing Guideline

## Filename

The filename's format should be `yyyy-mm-dd-title-of-the-post.md`.
All characters should be lowercases.
File extension should be `*.md`.
`*.markdown` works well also, but use `*.md`.

## Metadata

The first several lines between two `---` is metadatas.

```
---
layout: post
title: "PCTF 2016 - fixedpoint"
date: 2017-11-17 +0900
author: "JaeHyuk Lim"
categories: [write-up]
tags: [ctf, pwn, exploit]
---
```

### Layout

Layout should be `post`.
If it is not `post`, your post won't be displayed properly.

### Title

Insert your title.
If the title is one word, you don't need double quotation mark(`"`).

### Date

The foramt of the date is `yyyy-mm-dd +0900`. `+0900` means timezone.
As you know, KST is same as UTC+9.
It means, Korean Standard Time is 9 hours faster than UTC.
So, timezone should be `+0900` unless you are in foreign country that timezone is not UTC+9.
If you are in foreign country, you can use the local date and timezone.

### Author

Insert your name.

### Categories

Category should be listed like python list expression, like `[1st-category, 2nd-category, 3rd-category]`.
Category will be used to generate permlink.
So, don't use make it too deeply.

#### Existing Categories

* write-up  // ctf write-ups

### Tags

Tags should be listed like python list expression, like `[1st-tag, 2nd-tag, 3rd-tag]`.

#### Existing Tags

* ctf
* exploit
* pwn
