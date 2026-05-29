/* Sage Phone Login - Multi-account Selection Handler
   Called when user selects an account from the multi-account list
*/
window.sageSelectAccount = async function(selectedId) {
    var form = bricks.getWidgetById('phone_form', bricks.app);
    if (!form) return;
    var vals = form._getValue();

    var btn = bricks.getWidgetById('phone_login_btn', bricks.app);
    if (btn) { btn.disabled = true; if (btn.text_w) btn.text_w.set_otext('登录中...'); }

    var body = 'cellphone=' + encodeURIComponent(vals.cell_no)
        + '&key=' + encodeURIComponent(vals.codeid)
        + '&sms_code=' + encodeURIComponent(vals.check_code)
        + '&selected_id=' + encodeURIComponent(selectedId);

    // Get phone_login URL from the page context
    var baseUrl = bricks.app.baseUrl || '';
    var loginUrl = baseUrl + '/rbac/phone_login.dspy?_webbricks_=1';

    try {
        var resp = await fetch(loginUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body
        });
        var d = await resp.json();

        if (btn) { btn.disabled = false; if (btn.text_w) btn.text_w.set_otext('登录'); }

        if (d.status === 'ok') {
            var u = d.data.user;
            var nick = u.nick_name || u.username;
            var msgW = {
                widgettype: 'Message',
                options: { timeout: 3, auto_open: true, title: '登录成功', message: nick + ' 欢迎' },
                binds: [
                    { wid: 'self', event: 'dismissed', actiontype: 'script', target: 'self',
                      script: 'if(bricks.app&&bricks.app.dispatch)bricks.app.dispatch("user_logined")' },
                    { wid: 'self', event: 'dismissed', actiontype: 'script', target: 'body.login_window',
                      script: 'this.destroy()' }
                ]
            };
            var w = await bricks.widgetBuild(msgW, bricks.app);
            if (w) bricks.app.add_widget(w);
        } else {
            alert(d.data.message || '登录失败');
        }
    } catch (e) {
        if (btn) { btn.disabled = false; if (btn.text_w) btn.text_w.set_otext('登录'); }
        alert('网络错误: ' + e);
    }
};
