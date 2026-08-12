#import "typography.typ": 字体

#let outline-page() = [
  #set par(first-line-indent: 0em)

  #[
    #show heading: none
    #heading([目录], level: 1, outlined: false)
  ]

  #show outline.entry.where(level: 1): set text(font: 字体.黑体)

  #outline(title: align(center)[目录], indent: 1.5em)
]
