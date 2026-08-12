#import "conf.typ": doc, preface, main
#import "components/cover.typ": cover
#import "components/outline.typ": outline-page

#show: doc

#set text(lang: "zh", region: "cn")

#cover(
  title: "PulseOS决赛设计文档",
  institute: "郑州大学",
  year: 2026,
  month: 8,
)

#show: preface.with(title: "PulseOS决赛")
#outline-page()

#show: main

#include "content/problems.typ"
#include "content/qperf.typ"
#include "content/performance.typ"
#include "content/ai.typ"
