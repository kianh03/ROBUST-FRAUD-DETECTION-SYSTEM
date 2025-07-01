$(document).ready(function () {
    $("#checkButton").click(function () {
        var url = $("#urlInput").val();
        
        if (url.trim() === "") {
            alert("Please enter a URL.");
            return;
        }

        // Send request to Flask backend
        $.ajax({
            type: "POST",
            url: "/predict",
            contentType: "application/json",
            data: JSON.stringify({ url: url }),
            success: function (response) {
                console.log("Server Response:", response);  // Debugging

                // Update fraud score
                $("#result").html(
                    `<strong>Base URL:</strong> <span style="color:blue;">${response.base_url}</span> <br> 
                     <strong>Fraud Score:</strong> <span style="color:red;">${response.fraud_score}%</span>`
                );

                // Display feature breakdown with percentages
                let featureList = "<h3>Feature Breakdown</h3><ul>";
                for (let key in response.features) {
                    featureList += `<li><strong>${key}:</strong> ${response.features[key]} 
                                    (<span style="color:green;">${response.feature_percentages[key]}%</span>)</li>`;
                }
                featureList += "</ul>";

                $("#features").html(featureList);
            },
            error: function (xhr, status, error) {
                console.error("Error:", error);
                $("#result").html("<span style='color:red;'>Error processing the request.</span>");
            }
        });
    });
});
