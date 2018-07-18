package com.caodaxing.dao;

import com.caodaxing.entity.Role;
import com.caodaxing.entity.UserRole;
import com.caodaxing.entity.UserRoleExample;
import java.util.List;
import org.apache.ibatis.annotations.Param;

public interface UserRoleMapper {
    long countByExample(UserRoleExample example);

    int deleteByExample(UserRoleExample example);

    int deleteByPrimaryKey(Long id);

    int insert(UserRole record);

    int insertSelective(UserRole record);

    List<UserRole> selectByExample(UserRoleExample example);
    
    /**
     * 根据用户id查询对应的角色信息
     * @param userId
     * @return
     */
    List<Role> getRoleByUserId(Long userId);

    UserRole selectByPrimaryKey(Long id);

    int updateByExampleSelective(@Param("record") UserRole record, @Param("example") UserRoleExample example);

    int updateByExample(@Param("record") UserRole record, @Param("example") UserRoleExample example);

    int updateByPrimaryKeySelective(UserRole record);

    int updateByPrimaryKey(UserRole record);
}