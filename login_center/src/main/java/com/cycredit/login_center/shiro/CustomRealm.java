package com.cycredit.login_center.shiro;

import com.auth0.jwt.exceptions.TokenExpiredException;
import com.cycredit.login_center.mapper.MenuMapper;
import com.cycredit.login_center.util.JWTUtil;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.CollectionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class CustomRealm extends AuthorizingRealm {
    @Autowired
    private MenuMapper menuMapper;

    /**
     * 必须重写此方法，不然会报错
     */
    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof JWTToken;
    }

    /**
     * 清除所有用户授权信息缓存.
     */
    public void clearAllCachedAuthorizationInfo() {
        getAuthorizationCache().clear();
    }

    /**
     * 默认使用此方法进行用户名正确与否验证，错误抛出异常即可。
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken)
            throws AuthenticationException {
        String jwt = (String) authenticationToken.getCredentials();
        String username = null;
        try {
            username = JWTUtil.getUsername(jwt);
        } catch (Exception e){
            throw new AuthenticationException("token无效，请重新登录获取");
        }
        if (username == null){
            throw new AuthenticationException("token无效，请重新登录获取");
        }
        if (!JWTUtil.verify(jwt, username)) {
            throw new AuthenticationException("token已经失效，请重新登录！");
        } else {
            return new SimpleAuthenticationInfo(username, jwt,"CustomRealm");
        }
    }

    /**
     * 只有当需要检测用户权限的时候才会调用此方法，例如checkRole,checkPermission之类的
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String username = principals.toString();
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        // 获取用户权限
        Set<String> permList = menuMapper.findPerm(username);
        if (!CollectionUtils.isEmpty(permList)) {
            info.setStringPermissions(permList);
        }
        return info;
    }
}
