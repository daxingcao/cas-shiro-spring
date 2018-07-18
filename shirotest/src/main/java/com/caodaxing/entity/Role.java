package com.caodaxing.entity;

public class Role extends BaseEntity {
    /**
     * 角色id
     */
    private Long roleId;

    /**
     * 角色名
     */
    private String roleName;

    /**
     * 角色描述
     */
    private String roleRemark;

    public Long getRoleId() {
        return roleId;
    }

    public void setRoleId(Long roleId) {
        this.roleId = roleId;
    }

    public String getRoleName() {
        return roleName;
    }

    public void setRoleName(String roleName) {
        this.roleName = roleName;
    }

    public String getRoleRemark() {
        return roleRemark;
    }

    public void setRoleRemark(String roleRemark) {
        this.roleRemark = roleRemark;
    }

}