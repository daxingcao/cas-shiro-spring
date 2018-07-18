package com.caodaxing.service.impl;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.caodaxing.dao.UserRoleMapper;
import com.caodaxing.entity.Role;
import com.caodaxing.entity.UserRole;
import com.caodaxing.entity.UserRoleExample;
import com.caodaxing.service.UserRoleService;

@Service
public class UserRoleServiceImpl implements UserRoleService {

	@Autowired
	private UserRoleMapper userRoleMapper;
	
	@Override
	public long countByExample(UserRoleExample example) {
		return userRoleMapper.countByExample(example);
	}

	@Override
	public int insert(UserRole record) {
		return userRoleMapper.insert(record);
	}

	@Override
	public int insertSelective(UserRole record) {
		return userRoleMapper.insertSelective(record);
	}

	@Override
	public List<UserRole> selectByExample(UserRoleExample example) {
		return userRoleMapper.selectByExample(example);
	}

	@Override
	public UserRole selectByPrimaryKey(Long id) {
		return userRoleMapper.selectByPrimaryKey(id);
	}

	@Override
	public int updateByPrimaryKeySelective(UserRole record) {
		return userRoleMapper.updateByPrimaryKeySelective(record);
	}

	@Override
	public int updateByPrimaryKey(UserRole record) {
		return userRoleMapper.updateByPrimaryKey(record);
	}

	@Override
	public List<Role> getRoleByUserId(Long userId) {
		return userRoleMapper.getRoleByUserId(userId);
	}

}
