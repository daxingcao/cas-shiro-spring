<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Insert title here</title>
<link rel="stylesheet" href="<%=request.getContextPath() %>/static/css/bootstrap.min.css" />
<link rel="stylesheet" href="<%=request.getContextPath() %>/static/css/bootstrap-theme.css" />
<script src="<%=request.getContextPath() %>/static/javascript/jquery.min.js"></script>
<script src="<%=request.getContextPath() %>/static/javascript/bootstrap.min.js"></script>
<script src="<%=request.getContextPath() %>/static/javascript/jquery.validate.js"></script>
<style type="text/css">
.login_submit{
	width: 400px;
	margin: 100px auto;
	border-radius:5px;
	min-height: 550px;
	box-shadow: 0px 0px 10px #666;
}
.button-submit{
	width: 400px;
	margin: 50px auto;
	text-align: center;
}
.button-submit .btn-success{
	width: 200px;
}
.form-login{
	width: 200px;
	margin: 0px auto;
}
.login-icon{
	width: 100px;
	height: 100px;
	margin: 80px auto 50px auto;
}
.login_submit:before{
	content: '.';
	display: block;
	clear: both;
	font-size: 0;
	opacity: 0;
	line-height: 0;
	height: 0;
}
</style>
</head>
<body>
<div id="loginForm" class="login_submit">
	<div class="login-icon">
		<img style="width: 100px;height: 100px;border-radius: 50px;box-shadow: #666 0px 0px 20px;" src="static/image/tubiao.png">
	</div>
	<form id="loginSubmit" class="form-horizontal form-login">
		<div class="form-group">
		    <div class="col-sm-12" style="position: relative;">
		    	<i class="glyphicon glyphicon-user" style="position: absolute;top: 10px;left: 22px;"></i>
		    	<input type="text" class="form-control" name="username" placeholder="Email" style="padding-left: 30px;">
		    </div>
		</div>
		<div class="form-group">
		    <div class="col-sm-12" style="position: relative;">
		    	<i class="glyphicon glyphicon-lock" style="position: absolute;top: 10px;left: 22px;"></i>
		    	<input type="password" class="form-control" name="password" placeholder="Password" style="padding-left: 30px;">
		    </div>
		</div>
		<p id="error-info" class="hidden" style="color: red;">错误信息:</p>
	</form>
	<div class="button-submit">
		<button id="check-login" class="btn btn-success">登录</button><br>
		<button class="btn btn-link" style="padding-top: 10px;">没有账号?立即注册</button>
	</div>
</div>
</body>
<script type="text/javascript">
$(function(){        
        $("#loginSubmit").validate({
            /* debug:true, */
            rules:{
                username:{
                    required: true
                },
                password:{
                    required:true
                }
            },
            messages:{
                username:{
                    required:"用户名不能为空",
                    email:"请输入正确的邮箱格式！"
                },
                password:"密码不能为空！"
            }
        })
    })
$(".btn-link").click(function(){
    alert("sss...");
    location.href="index.html";
})
$("#check-login").click(function(){
    var valid = $("#loginSubmit").valid();
    if(valid){
        var formData = new FormData(document.getElementById("loginSubmit"));
        $.ajax({
            url:"${request.getContextPath()}checkLogin.do",
            data:formData,
            processData:false,
            contentType:false,
            type:"post",
            success:function(data){
                if(data.success){
                    window.location.href="index.do";
                }else {
                    $("#error-info").text(data.msg);
                    $("#error-info").attr("class","show");
                    $("#error-info").fadeOut(3000,function(){
                        $("#error-info").attr("class","hidden");
                    });
                }
            }
        })
    }
})
</script>
</html>