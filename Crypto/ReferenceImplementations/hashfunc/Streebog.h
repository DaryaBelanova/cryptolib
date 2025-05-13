#ifndef REFERENCEIMPLEMENTATIONS_STREEBOG_H
#define REFERENCEIMPLEMENTATIONS_STREEBOG_H

#include <vector>
#include <array>
#include <stdint.h>

namespace HashFunc {

    /*
    * ѕусть есть сообщение M3||M2||M1 (старшие байты наход€тс€ в M3).
    * ѕредполагаетс€, что сначала поступит блок M1, затем M2, в конце M3 (блоки в big endian).
    */

    class Streebog {
    public:

        Streebog();

        ~Streebog();

        void update(const std::vector<uint8_t>& src);

        void refresh();

        /*void hash(const std::vector<uint8_t>& src,
            const std::vector<uint8_t>& iv,
            std::vector<uint8_t> &dst);*/

        static const size_t byte_block_size = 64;

        void finalize(std::array<uint8_t, byte_block_size>& h_dst);

        friend class StreebogTest;

    protected:

        std::array<uint8_t, byte_block_size> h_;

    private:

        std::array<uint8_t, byte_block_size> last_block_; // in big endian order

        size_t last_block_size_;

        static const std::vector<uint8_t> pi_;

        static const std::vector<uint8_t> tau_;

        static const std::vector<std::vector<uint8_t>> A_matrix_;

        static const std::vector<std::vector<uint8_t>> iter_consts_;


        std::array<uint8_t, byte_block_size> N_;

        std::array<uint8_t, byte_block_size> sigma_;

        void X_transform(const std::array<uint8_t, byte_block_size>& src,
            const std::array<uint8_t, byte_block_size>& key,
            std::array<uint8_t, byte_block_size>& dst);

        void S_transform(const std::array<uint8_t, byte_block_size>& src,
            std::array<uint8_t, byte_block_size>& dst);

        void P_transform(const std::array<uint8_t, byte_block_size>& src,
            std::array<uint8_t, byte_block_size>& dst);

        void l_transform(const std::array<uint8_t, 8>& src,
            std::array<uint8_t, 8>& dst);

        void L_transform(const std::array<uint8_t, byte_block_size>& src,
            std::array<uint8_t, byte_block_size>& dst);

        void E_transform(const std::array<uint8_t, byte_block_size>& k,
            const std::array<uint8_t, byte_block_size>& m,
            std::array<uint8_t, byte_block_size>& dst);

        void gN(const std::array<uint8_t, byte_block_size>& h,
            const std::array<uint8_t, byte_block_size>& m,
            const std::array<uint8_t, byte_block_size>& N,
            std::array<uint8_t, byte_block_size>& dst);

    };

} // namespace HashFunc
 
#endif //REFERENCEIMPLEMENTATIONS_STREEBOG_H