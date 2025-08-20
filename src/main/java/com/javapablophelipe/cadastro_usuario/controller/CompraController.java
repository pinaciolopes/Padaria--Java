package com.javapablophelipe.cadastro_usuario.controller;

import com.javapablophelipe.cadastro_usuario.business.CompraService;
import com.javapablophelipe.cadastro_usuario.dto.CompraRequestDTO;
import com.javapablophelipe.cadastro_usuario.infrastructure.entitys.Compra;
import com.javapablophelipe.cadastro_usuario.infrastructure.repository.CompraRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/compras")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:63342")
public class CompraController {

    private final CompraRepository compraRepository;
    private final CompraService compraService;

    @PostMapping
    public ResponseEntity<Compra>criarCompra(@RequestBody CompraRequestDTO dto){
        Compra novaCompra = compraService.criarCompraComDTO(dto);
        return ResponseEntity.ok(novaCompra);
    }
}
