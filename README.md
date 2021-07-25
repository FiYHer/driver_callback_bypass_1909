# driver_callback_bypass_1909
研究和移除各种内核回调,在anti anti cheat的路上越走越远

# 测试系统
全部代码运行在1909系统下(Microsoft Windows [版本 10.0.18363.592])

# 更新
主要回调都绕过,分析出来自会上传,完毕后写一个专门的小工具

# 最新想法
使用shellcode在微软官方驱动里起一个CmRegisterCallback回调,在回调中跳转到我们的处理函数
