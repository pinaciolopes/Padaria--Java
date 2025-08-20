package com.javapablophelipe.cadastro_usuario.infrastructure.entitys;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.boot.context.properties.bind.Name;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Table(name = "tb_compra")
@Entity

public class Compra {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "usuario_id")
    private Usuario usuario;
    @ManyToMany
    @JoinTable(
           name = "tb_compra_produto",
           joinColumns = @JoinColumn(name = "compra_id"),
           inverseJoinColumns = @JoinColumn(name = "padaria_id")
    )

    private List<Padaria> produtos;

    @Column(name = "data_compra")
    private LocalDateTime dataCompra;

    @Column(name = "valor_total")
    private Double valorTotal;


}
