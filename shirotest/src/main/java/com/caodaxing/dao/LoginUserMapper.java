package com.caodaxing.dao;

import com.caodaxing.entity.LoginUser;
import com.caodaxing.entity.LoginUserExample;
import java.util.List;
import org.apache.ibatis.annotations.Param;

public interface LoginUserMapper {
    long countByExample(LoginUserExample example);

    int deleteByExample(LoginUserExample example);

    int deleteByPrimaryKey(Long id);

    int insert(LoginUser record);

    int insertSelective(LoginUser record);

    List<LoginUser> selectByExample(LoginUserExample example);

    LoginUser selectByPrimaryKey(Long id);

    int updateByExampleSelective(@Param("record") LoginUser record, @Param("example") LoginUserExample example);

    int updateByExample(@Param("record") LoginUser record, @Param("example") LoginUserExample example);

    int updateByPrimaryKeySelective(LoginUser record);

    int updateByPrimaryKey(LoginUser record);
}