#include "analysis.h"

double estimatePrecision(std::vector<std::complex<double>> &v1, std::vector<std::complex<double>> &v2) {
    double precVal=0.;
    uint32_t n=v1.size();
    for(size_t i=0; i<n; i++) {
        double prec=-std::log2(abs(v1[i].real()-v2[i].real())/abs(v2[i].real()));
        precVal+=prec;
    }
    return precVal/n;
}

double estimatePrecisionAbsolute(std::vector<std::complex<double>> &v1, std::vector<std::complex<double>> &v2) {
    double precVal=0.;
    uint32_t n=v1.size();
    for(size_t i=0; i<n; i++) {
        double prec=-std::log2(abs(v1[i].real()-v2[i].real()));
        precVal+=prec;
    }
    return precVal/n;
}

double estimatePrecisionInt(const std::vector<std::complex<double>> &v)
{
    double precVal=0.;
    uint32_t n=v.size();
    for(size_t i=0; i<n; i++) {
        double prec=-std::log2(abs(v[i].real()-std::round(v[i].real())));
        //std::cout << v[i].real() << " " << std::round(v[i].real()) << " " << prec << std::endl;
        precVal+=prec;
    }
    return precVal/n;
}