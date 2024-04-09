package cn.liulingfengyu.oauthserver.utils;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

public class OAuth2EndpointUtils {

    public static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
        // 获取请求参数映射表
        Map<String, String[]> parameterMap = request.getParameterMap();
        // 创建一个可修改的键值对集合
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap(parameterMap.size());
        // 遍历参数映射表
        parameterMap.forEach((key, values) -> {
            // 如果参数值数组长度大于0
            if (values.length > 0) {
                // 定义一个变量来引用参数值数组
                String[] var3 = values;
                // 获取参数值数组的长度
                int var4 = values.length;

                // 遍历参数值数组
                for (int var5 = 0; var5 < var4; ++var5) {
                    // 获取当前参数值
                    String value = var3[var5];
                    // 将参数名和参数值添加到集合中
                    parameters.add(key, value);
                }
            }

        });
        // 返回参数集合
        return parameters;
    }


    public static void throwError(String errorCode, String parameterName, String errorUri) {
        // 创建一个OAuth2Error对象，包含错误码、错误信息和错误URI
        OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
        // 抛出一个OAuth2AuthenticationException异常，包含上述创建的OAuth2Error对象
        throw new OAuth2AuthenticationException(error);
    }

}
