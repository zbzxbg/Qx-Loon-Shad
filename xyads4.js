/**
 * 星野 App Config 界面精简脚本
 */

let body = $response.body;

if (body) {
    try {
        let obj = JSON.parse(body);

        // 1. 禁用指定开关
        if ("enable_moment" in obj) obj.enable_moment = false;
        if ("enable_daily_check_in" in obj) obj.enable_daily_check_in = false;
        if ("enable_pay" in obj) obj.enable_pay = false;

        // 2. 清空聊天拓展工具箱列表 (隐藏全部实验室扩展)
        if (Array.isArray(obj.chat_lab_extensions)) {
            obj.chat_lab_extensions = [];
        }

        /* 如果您只想过滤掉特定几个工具（比如保留“穿搭”，删掉其他），
           可以取消下面代码的注释并替换上面的清空代码：

        if (Array.isArray(obj.chat_lab_extensions)) {
            obj.chat_lab_extensions = obj.chat_lab_extensions.filter(item => {
                return item.name !== "秘密空间" && item.name !== "高光视频";
            });
        }
        */

        $done({ body: JSON.stringify(obj) });
    } catch (e) {
        console.log("App Config 脚本解析异常: " + e);
        $done({});
    }
} else {
    $done({});
}
