let body = $response.body;

if (body) {
    try {
        let obj = JSON.parse(body);
        
        // 1. 判断数据结构是否存在，防止脚本报错
        if (obj.tab_list && obj.tab_list[0] && obj.tab_list[0].sub_tab_list) {
            
            // 2. 使用 filter 方法，保留那些名字 不是 "星工坊" 且 不是 "挑战" 的元素
            obj.tab_list[0].sub_tab_list = obj.tab_list[0].sub_tab_list.filter(item => {
                return item.name !== "星工坊" && item.name !== "挑战";
            });
            
            // 💡 进阶写法：如果你想根据 ID 隐藏，也可以这样写：
            // return item.id !== 90017 && item.id !== 90015;
        }
        
        // 3. 将修改后的数据返回
        $done({ body: JSON.stringify(obj) });
        
    } catch (e) {
        console.log("脚本修改失败: " + e);
        $done({});
    }
} else {
    $done({});
}
