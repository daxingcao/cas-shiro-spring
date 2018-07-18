package com.caodaxing.service;

import java.util.List;

import com.caodaxing.entity.Role;
import com.caodaxing.entity.UserRole;
import com.caodaxing.entity.UserRoleExample;

public interface UserRoleService {

	long countByExample(UserRoleExample example);

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

    int updateByPrimaryKeySelective(UserRole record);

    int updateByPrimaryKey(UserRole record);
	
}
