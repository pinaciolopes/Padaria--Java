package com.javapablophelipe.cadastro_usuario.dto;

import lombok.Data;

import java.util.List;
@Data

public class CompraRequestDTO {
    private Long usuarioId;
    private List<Long> produtosIds;
}
