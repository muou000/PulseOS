#import "typography.typ": 字体, 字号

#let cover(
  title: "",
  institute: "",
  year: datetime.today().year(),
  month: datetime.today().month(),
) = {
  place(top + left, dx: -1cm, dy: -1.8cm, image("../img/image.png", width: 50%))

  align(center)[

    #let space_scale_ratio = 1.2

    #v(3fr)

    #text(size: 字号.小一, font: 字体.宋体, weight: "bold")[*PulseOS初赛设计文档*]

    #v(4fr)

    #align(center)[
      #text(size: 字号.三号, font: 字体.楷体, weight: "bold")[#institute]

      #v(1em)

      #text(size: 字号.三号, font: 字体.楷体)[石家誉  孔梦琪]

      #v(2em)

      #text(size: 字号.小二, font: 字体.宋体, weight: "bold")[
        #[#year]年#[#month]月
      ]
    ]

    #v(2em)
  ]
}
