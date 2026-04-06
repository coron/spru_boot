#ifndef ANALYSIS_H
#define ANALYSIS_H

#include "openfhe.h"

double estimatePrecision(std::vector<std::complex<double>> &v1, std::vector<std::complex<double>> &v2);
double estimatePrecisionAbsolute(std::vector<std::complex<double>> &v1, std::vector<std::complex<double>> &v2);
double estimatePrecisionInt(const std::vector<std::complex<double>> &v);

#endif // ANALYSIS_H

