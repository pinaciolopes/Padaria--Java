const BASE_URL = "http://localhost:8080/api/padaria";

// Cadastrar novo produto
async function cadastrarProduto(produto) {
    const response = await fetch(BASE_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(produto)
    });

    if (response.status === 201) {
        alert("Produto cadastrado com sucesso!");
    } else {
        alert("Erro ao cadastrar produto.");
    }
}

// Buscar produto por ID
async function buscarProduto(id) {
    const response = await fetch(`${BASE_URL}/${id}`);
    if (response.ok) {
        const produto = await response.json();
        console.log("Produto:", produto);
        return produto;
    } else {
        alert("Produto não encontrado.");
    }
}

// Atualizar produto
async function atualizarProduto(id, novosDados) {
    const response = await fetch(`${BASE_URL}/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(novosDados)
    });

    if (response.ok) {
        alert("Produto atualizado com sucesso!");
    } else {
        alert("Erro ao atualizar produto.");
    }
}

// Deletar produto
async function deletarProduto(id) {
    const response = await fetch(`${BASE_URL}/${id}`, {
        method: "DELETE"
    });

    if (response.status === 204) {
        alert("Produto deletado com sucesso!");
    } else {
        alert("Erro ao deletar produto.");
    }
}
