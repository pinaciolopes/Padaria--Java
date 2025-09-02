package com.javapablophelipe.cadastro_usuario.dto;

import com.javapablophelipe.cadastro_usuario.role.UserRole;

public record RegisterDTO(String login, String password, UserRole role) {
}
