const Joi = require('joi');

const sslSchema = Joi.object({
  domain: Joi.string().hostname().required().messages({
    'string.base': 'Domain must be a string',
    'string.empty': 'Domain cannot be empty',
    'string.hostname': 'Domain must be a valid hostname',
    'any.required': 'Domain is required',
  }),
});

const validateSslRequest = (data) => {
  return sslSchema.validate(data);
};

module.exports = {
  validateSslRequest,
};
