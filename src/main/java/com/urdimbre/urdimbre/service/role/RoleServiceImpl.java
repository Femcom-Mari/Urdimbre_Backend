package com.urdimbre.urdimbre.service.role;

import java.util.List;

import org.springframework.stereotype.Service;

import com.urdimbre.urdimbre.dto.role.RoleRequestDTO;
import com.urdimbre.urdimbre.dto.role.RoleResponseDTO;
import com.urdimbre.urdimbre.exception.ResourceNotFoundException;
import com.urdimbre.urdimbre.model.Role;
import com.urdimbre.urdimbre.model.User;
import com.urdimbre.urdimbre.repository.RoleRepository;
import com.urdimbre.urdimbre.repository.UserRepository;

@Service
public class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;

    public RoleServiceImpl(RoleRepository roleRepository, UserRepository userRepository) {
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
    }

    @Override
    public RoleResponseDTO createRole(RoleRequestDTO roleDTO) {
        Role role = new Role();
        role.setName(roleDTO.getName());
        role.setDescription(roleDTO.getDescription());
        Role saved = roleRepository.save(role);
        return mapToResponseDTO(saved);
    }

    @Override
    public RoleResponseDTO updateRole(Long id, RoleRequestDTO roleDTO) {
        Role role = roleRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Rol", "id", id));
        role.setName(roleDTO.getName());
        role.setDescription(roleDTO.getDescription());
        Role updated = roleRepository.save(role);
        return mapToResponseDTO(updated);
    }

    @Override
    public RoleResponseDTO getRole(Long id) {
        Role role = roleRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Rol", "id", id));
        return mapToResponseDTO(role);
    }

    @Override
    public RoleResponseDTO getRoleByName(String name) {
        Role role = roleRepository.findByName(name)
                .orElseThrow(() -> new ResourceNotFoundException("Rol", "nombre", name));
        return mapToResponseDTO(role);
    }

    @Override
    public List<RoleResponseDTO> getAllRoles() {
        return roleRepository.findAll().stream()
                .map(this::mapToResponseDTO)
                .toList();
    }

    @Override
    public void deleteRole(Long id) {
        Role role = roleRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Rol", "id", id));
        roleRepository.delete(role);
    }

    public Long getUserIdByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("Usuario", "username", username));
        return user.getId();
    }

    private RoleResponseDTO mapToResponseDTO(Role role) {
        RoleResponseDTO dto = new RoleResponseDTO();
        dto.setId(role.getId());
        dto.setName(role.getName());
        dto.setDescription(role.getDescription());
        return dto;
    }
}