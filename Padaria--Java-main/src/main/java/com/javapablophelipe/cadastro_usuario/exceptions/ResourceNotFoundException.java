package com.javapablophelipe.cadastro_usuario.exceptions;

public class ResourceNotFoundException extends RuntimeException {

    public ResourceNotFoundException(String message) {
        super(message);
    }

    public ResourceNotFoundException(Long id) {
        super("Recurso não encontrada com o id " + id);
    }
}
