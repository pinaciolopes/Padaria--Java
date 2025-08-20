package com.javapablophelipe.cadastro_usuario.controller;

import com.javapablophelipe.cadastro_usuario.business.PadariaService;
import com.javapablophelipe.cadastro_usuario.infrastructure.entitys.Padaria;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/padaria")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:63342")

public class PadariaController {

    private final PadariaService padariaService;

    @PostMapping
    public ResponseEntity <Void> cadastrarProduto (@RequestBody Padaria padaria) {
        padariaService.cadastrarProduto(padaria);
        return ResponseEntity.ok().build();
    }
    @GetMapping
    public ResponseEntity<Padaria> buscarProdutoPorId (@RequestParam Long id) {
        return ResponseEntity.ok(padariaService.buscarProdutoPorId(id));

    }
    @DeleteMapping
    public ResponseEntity<Void> deletarProdutoPorId (@RequestParam Long id) {
        padariaService.deletarProdutoPorId(id);
        return ResponseEntity.ok().build();
    }
    @PutMapping("/{id}")
    public ResponseEntity<Void> atualizarPadaria (@RequestParam Long id, @RequestBody Padaria padaria) {
        padariaService.atualizarProdutoPorId(id, padaria);
        return ResponseEntity.ok().build();
    }
}
