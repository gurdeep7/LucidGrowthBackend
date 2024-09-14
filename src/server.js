const express = require('express');
const bodyParser = require('body-parser');
const sslRoutes = require('./routes/sslRoutes');
const cors = require('cors')

const app = express();
const port = 3001;

app.use(bodyParser.json());
app.use(cors())
app.use('/api', sslRoutes);


app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
