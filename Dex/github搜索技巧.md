以下为github 的限定词
in:name xxx ==> 限制搜索结果名字带有xxx的结果 
in:readme xxx ==> 过滤ReadMe.md中带有xxx的项目 
in:descriptions xxx ==> 过滤带有xxx字符的项目 
language: xxx ==>过滤xxx语言的项目 
stars:>xxx ==> 过滤超过xxx个星星的项目 
forks:>xxx ==> 同上 
pushed:>xxxx-xx-xx ==>过滤 某个日期后更新过的项目

demo: 
搜索 c语言的贪食蛇: 
in:description 贪食蛇 language:c stars:>100