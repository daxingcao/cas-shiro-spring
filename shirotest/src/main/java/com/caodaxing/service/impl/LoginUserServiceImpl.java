package com.caodaxing.service.impl;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.caodaxing.dao.LoginUserMapper;
import com.caodaxing.entity.LoginUser;
import com.caodaxing.entity.LoginUserExample;
import com.caodaxing.service.LoginUserService;

@Service
public class LoginUserServiceImpl implements LoginUserService {

	@Autowired
	private LoginUserMapper loginUserMapper;
	
	@Override
	public long countByExample(LoginUserExample example) {
		return loginUserMapper.countByExample(example);
	}

	@Override
	public int insert(LoginUser record) {
		return loginUserMapper.insert(record);
	}

	@Override
	public int insertSelective(LoginUser record) {
		return loginUserMapper.insertSelective(record);
	}

	@Override
	public List<LoginUser> selectByExample(LoginUserExample example) {
		return loginUserMapper.selectByExample(example);
	}

	@Override
	public LoginUser selectByPrimaryKey(Long id) {
		return loginUserMapper.selectByPrimaryKey(id);
	}

	@Override
	public int updateByPrimaryKeySelective(LoginUser record) {
		return loginUserMapper.updateByPrimaryKeySelective(record);
	}

	@Override
	public int updateByPrimaryKey(LoginUser record) {
		return loginUserMapper.updateByPrimaryKey(record);
	}

}
