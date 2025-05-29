package com.urdimbre.backend.service.role;

import java.util.List;

import com.urdimbre.backend.dto.role.RoleRequestDTO;
import com.urdimbre.backend.dto.role.RoleResponseDTO;

public interface RoleService {
    RoleResponseDTO createRole(RoleRequestDTO roleDTO);

    RoleResponseDTO updateRole(Long id, RoleRequestDTO roleDTO);

    RoleResponseDTO getRole(Long id);

    RoleResponseDTO getRoleByName(String name);

    List<RoleResponseDTO> getAllRoles();

    void deleteRole(Long id);
}