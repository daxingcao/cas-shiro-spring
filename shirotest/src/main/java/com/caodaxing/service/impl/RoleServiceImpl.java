package com.caodaxing.service.impl;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.caodaxing.dao.RoleMapper;
import com.caodaxing.entity.Role;
import com.caodaxing.entity.RoleExample;
import com.caodaxing.service.RoleService;

@Service
public class RoleServiceImpl implements RoleService {

	@Autowired
	private RoleMapper roleMapper;
	
	@Override
	public long countByExample(RoleExample example) {
		return roleMapper.countByExample(example);
	}

	@Override
	public int insert(Role record) {
		return roleMapper.insert(record);
	}

	@Override
	public int insertSelective(Role record) {
		return roleMapper.insertSelective(record);
	}

	@Override
	public List<Role> selectByExample(RoleExample example) {
		return roleMapper.selectByExample(example);
	}

	@Override
	public Role selectByPrimaryKey(Long roleId) {
		return roleMapper.selectByPrimaryKey(roleId);
	}

	@Override
	public int updateByPrimaryKeySelective(Role record) {
		return roleMapper.updateByPrimaryKeySelective(record);
	}

	@Override
	public int updateByPrimaryKey(Role record) {
		return roleMapper.updateByPrimaryKey(record);
	}

}
