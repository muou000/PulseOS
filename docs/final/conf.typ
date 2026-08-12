#import "components/typography.typ": 字体, 字号, main-format-heading, special-chapter-format-heading, heading-numbering

// 定义文档主页面样式
#let doc(content) = {
  set page(
    paper: "a4",
    margin: (top: 3.8cm, left: 3cm, right: 3cm, bottom: 3cm),
  )

  content
}

#let preface(content, title: "") = {
  set page(
    header: {
      [
        #set align(center)
        #set par(leading: 0em)
        #text(font: 字体.宋体, size: 字号.小五, baseline: 8.5pt)[
          #title 设计文档
        ]
        #line(length: 100%, stroke: 2.2pt)
        #v(2.2pt, weak: true)
        #line(length: 100%, stroke: 0.6pt)
      ]
    },
    header-ascent: 15%,
  )

  set page(numbering: "I")

  set page(
    footer: context [
      #align(center)[
        #counter(page).display("- I -")
      ]
    ],
    footer-descent: 15%,
  )

  counter(page).update(1)


  show heading: it => {
    set par(first-line-indent: 0em)

    if it.level == 1 {
      align(center)[
        #v(1em)
        #special-chapter-format-heading(it: it, font: 字体.黑体, size: 字号.小二)
        #v(.3em)
      ]
    } else {
      it
    }
  }


  set par(first-line-indent: 2em, leading: 1em, justify: true)

  set text(font: 字体.宋体, size: 字号.小四)

  content
}

// 正文页: 章节编号, 图表编号, 公式编号, 代码块优化, 引用处理
#let main(content) = {
  set page(numbering: "1")

  set page(footer: context [
    #align(center)[
      #counter(page).display("- 1 -")
    ]
  ])

  counter(page).update(1)

  set heading(numbering: heading-numbering)

  show heading: it => {
    set par(first-line-indent: 0em)

    if it.level == 1 {
      pagebreak(weak: true)
      align(center)[
        #v(1em)
        #main-format-heading(it: it, font: 字体.黑体, size: 字号.小二)
        #v(.3em)
      ]
    } else if it.level == 2 {
      main-format-heading(it: it, font: 字体.黑体, size: 字号.小三)
    } else if it.level >= 3 {
      main-format-heading(it: it, font: 字体.黑体, size: 字号.小四)
    }
  }

  show figure: set block(breakable: true)
  show figure.where(kind: "algorithm"): set figure.caption(position: top)

  show raw.where(block: false): box.with(
    fill: rgb("#fafafa"),
    inset: (x: 3pt, y: 0pt),
    outset: (y: 3pt),
    radius: 2pt,
  )

  show raw.where(block: false): text.with(
    font: 字体.代码,
    size: 10.5pt,
  )
  show raw.where(block: true): block.with(
    fill: rgb("#fafafa"),
    inset: 8pt,
    radius: 4pt,
    width: 100%,
  )
  show raw.where(block: true): text.with(
    font: 字体.代码,
    size: 10.5pt,
  )

  show link: it => {
    text(blue, it.body) // 示例：蓝色文本，无下划线
  }
  content
}
