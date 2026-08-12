#import "conf.typ": doc, preface, main
#import "components/cover.typ": cover
#import "components/figure.typ": algorithm-figure, code-figure
#import "components/outline.typ": outline-page
#import "@preview/lovelace:0.2.0": *

#show: doc

#set text(lang: "zh", region: "cn")

#cover(
  institute: "郑州大学",
)

#show: preface.with(title: "PulseOS")

#outline-page()

#show: main

#include "content/general.typ"
#include "content/memory.typ"
#include "content/thread.typ"
#include "content/filesystem.typ"
#include "content/signal.typ"
#include "content/net.typ"
#include "content/conclusion.typ"
