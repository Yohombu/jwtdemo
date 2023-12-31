package com.mycompany.jwtdemo.controller;


import com.mycompany.jwtdemo.entity.RoleEntity;
import com.mycompany.jwtdemo.model.RoleModel;
import com.mycompany.jwtdemo.service.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
public class RoleController {

    @Autowired
    private RoleService roleService;

    @PostMapping("/roles")
    public RoleModel createRole(@RequestBody RoleModel roleModel){
        return roleService.createRole(roleModel);
    }

    @GetMapping("/roles")
    public List<RoleModel> getAllRoles(){
        return roleService.getAllRoles();
    }

    @DeleteMapping("/role/{roleId}")
    public void deleteRole(@PathVariable Long roleId){
        roleService.deleteRoleById(roleId);
    }
}
