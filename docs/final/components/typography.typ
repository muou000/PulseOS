/*
 * 定义字号, 字体映射表
 * 提供标题排版宏和编号风格宏
 */
#let 字号 = (
  一英寸: 72pt,
  大特号: 63pt,
  特号: 54pt,
  初号: 42pt,
  小初: 36pt,
  一号: 26pt,
  小一: 24pt,
  二号: 22pt,
  小二: 18pt,
  三号: 16pt,
  小三: 15pt,
  四号: 14pt,
  小四: 12pt,
  五号: 10.5pt,
  小五: 9pt,
  六号: 7.5pt,
  小六: 6.5pt,
  七号: 5.5pt,
  八号: 5pt,
)

// 保持宋体、楷体、黑体和代码字体角色；无对应字体的环境可通过 --input 覆盖。
#let song-font = sys.inputs.at("song-font", default: ("Times New Roman", "SimSun"))
#let kai-font = sys.inputs.at("kai-font", default: ("Times New Roman", "KaiTi"))
#let hei-font = sys.inputs.at("hei-font", default: ("Times New Roman", "Microsoft YaHei", "SimHei"))
#let code-font = sys.inputs.at("code-font", default: ("Consolas", "Courier New", "KaiTi"))

#let 字体 = (
  宋体: song-font,
  楷体: kai-font,
  黑体: hei-font,
  代码: code-font,
)

// 定义章节标题的特殊格式宏
#let special-chapter-format-heading(it: none, font: none, size: none, weight: "regular") = {
  set text(font: font, size: size)

  text(weight: weight)[
    #if it != none {
      it.body
    }
  ]
  v(0.5em)
}

#let main-format-heading(it: none, font: none, size: none, weight: "regular") = {
  set text(font: font, size: size)

  text(weight: weight)[
    #counter(heading).display()
    #if it != none {
      it.body
    }
  ]
  v(0.5em)
}

#let heading-numbering(..nums) = {
  let nums-vec = nums.pos()

  if nums-vec.len() == 1 [
    #numbering("第 1 章", ..nums-vec) #h(0.75em)
  ] else [
    #numbering("1.1", ..nums-vec) #h(0.75em)
  ]
}
