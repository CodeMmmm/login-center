package com.cycredit.login_center.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * @author helang
 * @date 2021/12/2
 */
@Component
@Mapper
public interface MenuMapper extends BaseMapper {
    @Select("select m.perms from menu m left join role_menu rm on m.id = rm.menu_id where rm.role_id = " +
            "(select role_id from user where account = #{username}) ")
    Set<String> findPerm(String username);
}
