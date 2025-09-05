// CADASTRAR USUÁRIO
document.getElementById("formUsuario").addEventListener("submit", async function (e) {
    e.preventDefault();

    const usuario = {
        nome: document.getElementById("nome").value,
        cpf: document.getElementById("cpf").value,
        dataNascimento: document.getElementById("dataNascimento").value,
        email: document.getElementById("email").value,
        telefone: document.getElementById("telefone").value
    };

    try {
        const response = await fetch("http://localhost:8080/usuario", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(usuario)
        });

        if (response.status === 201 || response.status === 200) {
            alert("Usuário cadastrado com sucesso!");
            document.getElementById("formUsuario").reset();
        } else {
            alert("Erro ao cadastrar usuário.");
        }
    } catch (error) {
        alert("Erro de conexão com o servidor.");
        console.error(error);
    }
});

// BUSCAR USUÁRIO POR CPF
async function buscarUsuario() {
    const cpf = document.getElementById("buscarCpf").value;

    try {
        const response = await fetch(`https://padaria-java.onrender.com/usuario?cpf=${cpf}`);

        if (response.ok) {
            const usuario = await response.json();
            document.getElementById("resultado").textContent = JSON.stringify(usuario, null, 2);
        } else {
            document.getElementById("resultado").textContent = "Usuário não encontrado.";
        }
    } catch (error) {
        document.getElementById("resultado").textContent = "Erro ao buscar usuário.";
        console.error(error);
    }
}

// ATUALIZAR USUÁRIO POR CPF
async function atualizarUsuario() {
    const cpf = document.getElementById("cpfAtualizar").value;

    const usuarioAtualizado = {
        nome: document.getElementById("nomeAtualizar").value,
        email: document.getElementById("emailAtualizar").value,
        telefone: document.getElementById("telefoneAtualizar").value,
        dataNascimento: document.getElementById("dataNascimentoAtualizar").value
    };

    try {
        const response = await fetch(`https://padaria-java.onrender.com/usuario/${cpf}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(usuarioAtualizado)
        });

        if (response.ok) {
            alert("Usuário atualizado com sucesso!");
        } else {
            alert("Erro ao atualizar usuário.");
        }
    } catch (error) {
        alert("Erro de conexão com o servidor.");
        console.error(error);
    }
}

// DELETAR USUÁRIO POR CPF
async function deletarUsuario() {
    const cpf = document.getElementById("cpfDeletar").value;

    try {
        const response = await fetch(`https://padaria-java.onrender.com/usuario/${cpf}`, {
            method: "DELETE"
        });

        if (response.ok) {
            alert("Usuário deletado com sucesso!");
        } else {
            alert("Erro ao deletar usuário.");
        }
    } catch (error) {
        alert("Erro de conexão com o servidor.");
        console.error(error);
    }
}

// LISTAR TODOS OS USUÁRIOS
async function listarUsuarios() {
    try {
        const response = await fetch("https://padaria-java.onrender.com/usuarios");

        if (response.ok) {
            const usuarios = await response.json();
            document.getElementById("listaUsuarios").textContent = JSON.stringify(usuarios, null, 2);
        } else {
            document.getElementById("listaUsuarios").textContent = "Erro ao buscar lista.";
        }
    } catch (error) {
        document.getElementById("listaUsuarios").textContent = "Erro de conexão.";
        console.error(error);
    }
}
