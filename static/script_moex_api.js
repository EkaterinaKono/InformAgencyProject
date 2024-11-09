document.getElementById('dataForm').onsubmit = function(event) {
            event.preventDefault(); // Prevent default form submission

            const formData = new FormData(this);
            fetch('/submit', {
                method: 'POST',
                body: formData,
            })
            .then(response => response.json())
            .then(data => {
                const graphDiv = document.getElementById('graph');
                graphDiv.innerHTML = ''; // Clear previous graph

                const graphData = JSON.parse(data.graph_json);
                Plotly.newPlot(graphDiv, graphData.data, graphData.layout);
            });
        };