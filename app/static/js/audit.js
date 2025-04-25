function formatLogDetails(operation, details) {
  if (typeof details === "string") {
    return details;
  }

  switch (operation.toUpperCase()) {
    case "UPDATE":
      return `Updated file from "${details.old_filename}" to "${details.new_filename}"`;
    case "UPLOAD":
      return `Uploaded file "${details.filename}"`;
    case "DOWNLOAD":
      return `Downloaded file "${details.filename}"`;
    case "DELETE":
      return `Deleted file "${details.filename}"`;
    default:
      return JSON.stringify(details);
  }
}

function displayAuditLogs(logs) {
  const auditTable = document.getElementById("audit-table");
  const tbody = auditTable.querySelector("tbody");
  tbody.innerHTML = "";

  logs.forEach((log) => {
    const row = document.createElement("tr");

    const timestampCell = document.createElement("td");
    timestampCell.textContent = new Date(log.timestamp).toLocaleString();

    const operationCell = document.createElement("td");
    operationCell.textContent = log.operation;

    const detailsCell = document.createElement("td");
    detailsCell.textContent = formatLogDetails(log.operation, log.details);

    row.appendChild(timestampCell);
    row.appendChild(operationCell);
    row.appendChild(detailsCell);

    tbody.appendChild(row);
  });
}
