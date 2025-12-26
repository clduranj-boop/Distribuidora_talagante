// static/core/js/admin.js
document.addEventListener('DOMContentLoaded', function() {
    const forms = document.querySelectorAll('.update-status-form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            const ordenId = this.action.split('/').slice(-2, -1)[0];  // Extrae ID de la URL

            fetch(this.action, {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'  // Para identificar AJAX
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Actualiza el estado en la tabla sin recargar
                    const estadoCell = document.querySelector(`#orden-${ordenId}-estado`);
                    estadoCell.textContent = data.nuevo_estado;
                    alert('Estado actualizado con éxito!');
                } else {
                    alert(data.message || 'Error al actualizar');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error en la conexión');
            });
        });
    });
});