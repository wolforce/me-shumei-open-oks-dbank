package me.shumei.open.oks.dbank;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;

import org.json.JSONObject;
import org.jsoup.Connection.Method;
import org.jsoup.Connection.Response;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import android.content.Context;

/**
 * 使签到类继承CommonData，以方便使用一些公共配置信息
 * @author wolforce
 *
 */
public class Signin extends CommonData {
	String resultFlag = "false";
	String resultStr = "未知错误！";
	
	/**
	 * <p><b>程序的签到入口</b></p>
	 * <p>在签到时，此函数会被《一键签到》调用，调用结束后本函数须返回长度为2的一维String数组。程序根据此数组来判断签到是否成功</p>
	 * @param ctx 主程序执行签到的Service的Context，可以用此Context来发送广播
	 * @param isAutoSign 当前程序是否处于定时自动签到状态<br />true代表处于定时自动签到，false代表手动打开软件签到<br />一般在定时自动签到状态时，遇到验证码需要自动跳过
	 * @param cfg “配置”栏内输入的数据
	 * @param user 用户名
	 * @param pwd 解密后的明文密码
	 * @return 长度为2的一维String数组<br />String[0]的取值范围限定为两个："true"和"false"，前者表示签到成功，后者表示签到失败<br />String[1]表示返回的成功或出错信息
	 */
	public String[] start(Context ctx, boolean isAutoSign, String cfg, String user, String pwd) {
		//把主程序的Context传送给验证码操作类，此语句在显示验证码前必须至少调用一次
		CaptchaUtil.context = ctx;
		//标识当前的程序是否处于自动签到状态，只有执行此操作才能在定时自动签到时跳过验证码
		CaptchaUtil.isAutoSign = isAutoSign;
		
		try{
			//存放Cookies的HashMap
			HashMap<String, String> cookies = new HashMap<String, String>();
			//Jsoup的Response
			Response res;
			//Jsoup的Document
			Document doc;
			
			
			/*
			 * 签到数据分析参考：http://chenall.net/post/dbank_login/
			 * 
			快速自动签到方法，只需点击一个链接就可以自动签到无需密码，无需登录。本文测试帐号的自动签到链接如下
			http://api.dbank.com/rest.php?nsp_svc=com.dbank.signin.signin&anticache=383&nsp_sid=wuTubNKuCQi1muaOXx-uu4FjnYp182zozF58ZBk1HSNkFwED&nsp_ts=1341032380236&nsp_key=9AC41E0B0DD240F97361F87483131667&nsp_fmt=JS&nsp_cb=_jqjsp
			如果获取到上面的链接呢？最简单的方法直接抓包就行了，用chrome就可以直接抓包了。
			当然可以手工打造一个链接，要生成这个链接首先要知道各个参数是如何得来的。
			上面的链接参数解释(其中不重要的参数可以不要)
			第一个nsp_svc是固定的，表示要进行签到
			nsp_svc=com.dbank.signin.signin
			第二个参数是一个随机数字，不重要，你可以固定使用以下数值
			anticache=383
			nsp_sid 身份标志信息，这个就是cookie里面的session的值
			nsp_sid=kuTubNkuCQi19uaOXxiuu4FjMYp18kTozF5VnBk1HnAkFwEv
			这个不需要解释了，是一个时间串，不是很重要，同样可以固定
			nsp_ts=1341032380236
			验证信息，通过多种参数进行组合再进行MD5加密的结果
			nsp_key=9AC41E0B0DD240F97361F87483131667
			以下是固定的，不重要，不用管它。
			nsp_fmt=JS
			nsp_cb=_jqjsp
			看了上面的参数列表，基本上都是现成的，只有nsp_key需要额外获取。
			这个nsp_key的获取方法。
			1.把上面除了nsp_key之外的参数按字母正向排序一下,得到如下结果。
			anticache=383
			nsp_cb=_jqjsp
			nsp_fmt=JS
			nsp_sid=wuTubNKuCQi1muaOXx-uu4FjnYp182zozF58ZBk1HSNkFwED
			nsp_svc=com.dbank.signin.signin
			nsp_ts=1341032380236
			2.去掉参数中间的"="合成一串得到
			anticache383nsp_cb_jqjspnsp_fmtJSnsp_sidwuTubNKuCQi1muaOXx-uu4FjnYp182zozF58ZBk1HSNkFwEDnsp_svccom.dbank.signin.signinnsp_ts1341032380236
			3.获取cookie里面的secret的值接在上一步的前面比如是325c8b0ee26aa42cd4a4c20326a97a98
			那最终得到的字符串如下
			325c8b0ee26aa42cd4a4c20326a97a98anticache383nsp_cb_jqjspnsp_fmtJSnsp_sidwuTubNKuCQi1muaOXx-uu4FjnYp182zozF58ZBk1HSNkFwEDnsp_svccom.dbank.signin.signinnsp_ts1341032380236
			4.把上一步的字符串进行MD5计算就得到了nsp_key的值了
			9AC41E0B0DD240F97361F87483131667
			现在所有参数都有了，组合成前面的链接就行了，这个链接经过我测试就像前面的自动登录链接一下一直有效。
			需要自动签到很简单，只需要定时打开该链接就行了，根据返回的结果还可以获取签到的结果。

			EDIT2: 经测试，那些参数中有一些是可以不要的。重新整理一下必备参数如下.只有需要两个参数了。
			nsp_sid=wuTubNKuCQi1muaOXx-uu4FjnYp182zozF58ZBk1HSNkFwED
			nsp_svc=com.dbank.signin.signin
			nsp_ts 参数后面的值可以不要，但nsp_ts字符串须要有
			结合在一起的字符串就是这样子的。
			nsp_sidwuTubNKuCQi1muaOXx-uu4FjnYp182zozF58ZBk1HSNkFwEDnsp_svccom.dbank.signin.signinnsp_ts
			前面加上secret的值计算MD5比如我的得到
			325c8b0ee26aa42cd4a4c20326a97a98nsp_sidwuTubNKuCQi1muaOXx-uu4FjnYp182zozF58ZBk1HSNkFwEDnsp_svccom.dbank.signin.signinnsp_ts
			*/
			
			String authorUrl = "http://login.dbank.com/loginauth.php?nsp_app=48049";//获取登录授权的链接
			String finalAuthorUrl;//构造出的登录授权链接
			String loginUrl;//登录账号的链接
			String signUrl;//签到链接
			String tencentWeiBoUrl;//模拟发送腾讯微博的链接
			String sinaWeiBoUrl;//模拟发送新浪微博的链接
			String visitHao123Url;//模拟访问Hao123的链接
			
			//构造获取授权的链接
			res = Jsoup.connect(authorUrl).userAgent(UA_IE8).referrer(authorUrl).timeout(TIME_OUT).ignoreContentType(true).method(Method.GET).execute();
			cookies.putAll(res.cookies());
			doc = res.parse();
			String nonce = doc.getElementById("nonce").val();
			String nsp_cid = doc.getElementById("nsp_cid").val();
			String pwd_encrypt = MD5.md5(user + ":NSP Passport:" + pwd).toLowerCase();
			String response = MD5.md5(pwd_encrypt + ":" + nonce).toLowerCase();
			finalAuthorUrl = authorUrl + "&m=1&nonce=" + nonce + "&nsp_cid=" + nsp_cid + "&nsp_user=" + user +"&response=" + response;
			
			res = Jsoup.connect(finalAuthorUrl).userAgent(UA_IE8).referrer(authorUrl).timeout(TIME_OUT).ignoreContentType(true).method(Method.GET).execute();
			cookies.putAll(res.cookies());
			JSONObject jsonObj = new JSONObject(res.body());
			int retcode = jsonObj.getInt("retcode");
			
			if(retcode == 0)
			{
				String k = jsonObj.getString("k");
				loginUrl = "http://login.dbank.com/loginauth.php?k=" + k;
				
				res = Jsoup.connect(loginUrl).userAgent(UA_IE8).referrer(authorUrl).timeout(TIME_OUT).ignoreContentType(true).method(Method.GET).execute();
				cookies.putAll(res.cookies());
				//System.out.println(cookies);
				
				//把参数名和参数值用特殊字符串链接起来存放到ArrayList里面，就可以根据参数名对值进行排序了
				String secret = cookies.get("secret");
				String nsp_sid = "nsp_sid@@" + cookies.get("session");
				ArrayList<String> param = new ArrayList<String>();
				signUrl = getDBankAPIUrl(secret, nsp_sid, "nsp_svc@@com.dbank.signin.signin", param);//根据API获取签到链接
				
				//{"retcode":"0000","retdesc":"用户签到成功","type":2,"space":37}
				//{"retcode":"0001","retdesc":"用户已签到"}
				res = Jsoup.connect(signUrl).cookies(cookies).userAgent(UA_IE8).referrer(authorUrl).timeout(TIME_OUT).ignoreContentType(true).method(Method.GET).execute();
				jsonObj = new JSONObject(res.body());
				String returncode = jsonObj.getString("retcode");
				//String retdesc = jsonObj.getString("retdesc");
				if(returncode.equals("0000"))
				{
					resultFlag = "true";//签到成功
					boolean isSentWeiboFlag = false;//是否已经发送了微博
					boolean isVisitHao123 = false;//是否已经访问了hao123
					ArrayList<String> paramHao123 = new ArrayList<String>();
					ArrayList<String> paramQQ = new ArrayList<String>();
					ArrayList<String> paramSina = new ArrayList<String>();
					paramHao123.add("signtype@@7");
					paramQQ.add("signtype@@8");
					paramSina.add("signtype@@9");
					
					//visitHao123Url = getDBankAPIUrl(secret, nsp_sid, "nsp_svc@@com.dbank.signin.isForword", paramHao123);//访问hao123，+100M
					visitHao123Url = getDBankAPIUrl(secret, nsp_sid, "nsp_svc@@com.dbank.signin.forwordsign", paramHao123);//访问hao123，+100M
					tencentWeiBoUrl = getDBankAPIUrl(secret, nsp_sid, "nsp_svc@@com.dbank.signin.forwordsign", paramQQ);//腾讯微博转发，+1M
					sinaWeiBoUrl = getDBankAPIUrl(secret, nsp_sid, "nsp_svc@@com.dbank.signin.forwordsign", paramSina);//新浪微博转发，+1M
					int space = jsonObj.getInt("space");//签到获得的容量数
					int totalSpace = space;//总容量
					
					//模拟访问hao123失败时，最多重试retryTiems次
					for(int i=0;i<RETRY_TIMES;i++)
					{
						try {
							//{"retcode":"0000","retdesc":"用户未转发"}
							//{"retcode":"0003","retdesc":"用户已转发"}
							//{"retcode":"0000","retdesc":"成功"}
							res = Jsoup.connect(visitHao123Url).cookies(cookies).userAgent(UA_IE8).timeout(TIME_OUT).referrer(authorUrl).ignoreContentType(true).method(Method.GET).execute();
							System.out.println(res.body());
							if(res.body().contains("0000")) {
								totalSpace += 100;//访问hao123可以增加100M空间
								isVisitHao123 = true;//访问hao123成功
							} else {
								isVisitHao123 = false;
							}
							break;//一旦模拟访问成功就跳出重试
						} catch (Exception e) {
							isVisitHao123 = false;//访问hao123失败
						}
					}
					
					//模拟发送微博失败时，最多再进行retryTimes次重试
					for(int i=0;i<RETRY_TIMES;i++)
					{
						try {
							res = Jsoup.connect(tencentWeiBoUrl).cookies(cookies).userAgent(UA_IE8).timeout(TIME_OUT).referrer(authorUrl).ignoreContentType(true).method(Method.GET).execute();
							System.out.println(res.body());
							res = Jsoup.connect(sinaWeiBoUrl).cookies(cookies).userAgent(UA_IE8).timeout(TIME_OUT).referrer(authorUrl).ignoreContentType(true).method(Method.GET).execute();
							System.out.println(res.body());
							totalSpace += 2;
							isSentWeiboFlag = true;//发送微博成功
							break;//一旦模拟发送微博成功就跳出重试
						} catch (Exception e) {
							isSentWeiboFlag = false;//发送微博失败
						}
					}
					
					StringBuilder sb = new StringBuilder();
					sb.append("签到成功，获得" + space + "M空间，");
					if(isSentWeiboFlag) {
						sb.append("模拟发送新浪和腾讯微博成功，获得2M空间，");
					} else {
						sb.append("模拟发送新浪和腾讯微博失败，");
					}
					
					if(isVisitHao123) {
						sb.append("模拟访问Hao123成功，获得100M空间，");
					} else {
						sb.append("模拟访问Hao123失败\n");
					}
					
					sb.append("共获得" + totalSpace + "M空间");
					this.resultStr = sb.toString();
				}
				else
				{
					resultFlag = "true";
					resultStr = "今日已签过到";
				}
			}
			else
			{
				resultFlag = "false";
				resultStr = "登录失败";
			}
			
		} catch (IOException e) {
			this.resultFlag = "false";
			this.resultStr = "连接超时";
			e.printStackTrace();
		} catch (Exception e) {
			this.resultFlag = "false";
			this.resultStr = "未知错误！";
			e.printStackTrace();
		}
		
		return new String[]{resultFlag, resultStr};
	}
	
	
	/**
	 * 获取华为网盘的API链接
	 * @param secret
	 * @param nsp_sid
	 * @param nsp_svc
	 * @param params
	 * @return
	 */
	public String getDBankAPIUrl(String secret, String nsp_sid, String nsp_svc, ArrayList<String> params)
	{
		String nsp_ts = "nsp_ts@@" + new Date().getTime();
		params.add(nsp_sid);
		params.add(nsp_svc);
		params.add(nsp_ts);
		String url = "http://api.dbank.com/rest.php?";
		String str = secret;
		
		//顺序排序数组
		Collections.sort(params);
		
		//拼接URL
		for(String param:params)
		{
			String[] tempArr = param.split("@@");
			String key = tempArr[0];
			String value = tempArr[1];
			url += key + "=" + value + "&";
			str += key + value;
		}
		url += "nsp_key=" + MD5.md5(str);
		return url;
	}
	
	
}
