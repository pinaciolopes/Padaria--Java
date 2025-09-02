async function finalizarCompra() {
    const usuarioId = document.getElementById("usuarioId").value;

    // Suponha que produtosSelecionados seja um array com os IDs dos produtos do carrinho
    const produtosSelecionados = [1, 2, 3]; // Trocar pelos reais IDs dos produtos selecionados

    const compra = {
        usuarioId: parseInt(usuarioId),
        produtosIds: produtosSelecionados
    };

    try {
        const response = await fetch("http://localhost:8080/api/compra", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(compra)
        });

        if (response.status === 201) {
            const dadosCompra = await response.json();
            alert("Compra finalizada com sucesso! Total: R$ " + dadosCompra.valorTotal);
        } else {
            alert("Erro ao finalizar compra.");
        }
    } catch (error) {
        alert("Erro de conexão com o servidor.");
        console.error(error);
    }
}
