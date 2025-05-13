#ifndef REFERENCEIMPLEMENTATIONS_CTR_H
#define REFERENCEIMPLEMENTATIONS_CTR_H

#include <array>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <bitset>

    /*
     * Принимается, что для полноблоковых сообщений гамма берется равной блоку.
     * Если сообщение меньше блока шифрования, берется часть гаммы, равная текущему сообщению.
     * Сообщение, отправленное частями, шифруется на одном ключе так же, как если бы его отправили целиком.
     * (То есть неиспользованнная часть гаммы используется при последующей досылке сообщения.
     *  Работает корректно при условии, что последующая досылаемая часть дополняет последнюю часть предыдущего
     *  сообщения до полного блока, если она была меньше блока).
     */

     /*
      * NB
      * если вызвать refresh_iter_keys, то есть обновить ключ у экземпляра шифратора,
      * экземпляр режима с этим шифратором не будет ничего об этом знать, хотя должен обновить iv и гамму.
     */

     /*
     * Гамма вычисляется перед непосредственным использованием.
     */

    template <typename CipherType>
    class CTR {

    public:

        // must be called for every new message (not for a part of a message being sent in future).
        // this method does not reinitialize class fields but only refreshes them with new values.
        void refresh_iv(const std::vector<uint8_t>& iv) {
            std::copy(iv.begin(), iv.end(), iv_.begin());
            std::copy(iv.begin(), iv.end(), curr_ctr_.begin()); // copy to first n/2 positions iv
            std::fill(curr_ctr_.begin() + CipherType::byte_block_size / 2, curr_ctr_.end(), 0); // set to last n/2 positions 0
            curr_gamma_.fill(0);
            // necessary for gamma initialization for first block processing of plaintext
            curr_unused_gamma_idx_ = CipherType::byte_block_size;
        }

        /*CTR(CipherType& alg) : algorithm_(alg) {
            iv_ = {};
            curr_ctr_ = {};
            curr_gamma_ = {};
        }*/

        CTR(CipherType& alg, const std::vector<uint8_t> iv) : algorithm_(alg) {

            // initialization of all fields with required size
            iv_ = {};
            curr_ctr_ = {};
            curr_gamma_ = {};

            // fill all fields with passed value
            refresh_iv(iv);
        }

        //CTR(const std::array<uint8_t, 32> &key, const std::vector<uint8_t> iv) : algorithm_(key) {

        //    // initialization of all fields with required size
        //    iv_ = {};
        //    curr_ctr_ = {};
        //    curr_gamma_ = {};

        //    // fill all fields with passed value
        //    refresh_iv(iv);
        //}

        void encrypt(const std::vector<uint8_t>& src, std::vector<uint8_t>& dst);

        void decrypt(const std::vector<uint8_t>& src, std::vector<uint8_t>& dst);

        friend class CTRTest;

    private:

        std::array<uint8_t, CipherType::byte_block_size / 2> iv_;

        std::array<uint8_t, CipherType::byte_block_size> curr_ctr_;
        std::array<uint8_t, CipherType::byte_block_size> curr_gamma_;
        size_t curr_unused_gamma_idx_;

        CipherType algorithm_;

        void increment(std::array<uint8_t, CipherType::byte_block_size>& ctr);
    };


    template<typename CipherType>
    void CTR<CipherType>::increment(std::array<uint8_t, CipherType::byte_block_size>& ctr) {
        std::array<uint8_t, CipherType::byte_block_size> storage = {};
        uint8_t carry = 0;
        uint16_t total = ctr[CipherType::byte_block_size - 1] + 1 + carry;
        storage[CipherType::byte_block_size - 1] = total & 0xFF;
        carry = (total >> 8) & 0xFF;
        for (int i = CipherType::byte_block_size - 2; i >= 0; --i) {
            total = ctr[i] + carry;
            storage[i] = total & 0xFF;
            carry = (total >> 8) & 0xFF;
        }
        std::copy(storage.begin(), storage.end(), ctr.begin());
    }

    template<typename CipherType>
    void CTR<CipherType>::encrypt(const std::vector<uint8_t>& src, std::vector<uint8_t>& dst) {
        if (iv_.empty()) {
            throw "IV must be providen. Required to call method refresh_iv(iv) ";
        }

        if (src.empty()) {
            return;
        }

        std::vector<uint8_t> tmp_src(src.size());
        std::copy(src.begin(), src.end(), tmp_src.begin());

        std::vector<uint8_t> curr_block = {};
        dst = {};
        dst.resize(tmp_src.size());
        for (int i = 0; i < tmp_src.size(); i += CipherType::byte_block_size) {
            auto end_of_block = (i + CipherType::byte_block_size < tmp_src.size()) ?
                tmp_src.begin() + i + CipherType::byte_block_size :
                tmp_src.end();

            curr_block.resize(std::min(tmp_src.size(), i + CipherType::byte_block_size) - i);

            std::copy(tmp_src.begin() + i, end_of_block, curr_block.begin());

            if (curr_unused_gamma_idx_ == CipherType::byte_block_size) {
                curr_unused_gamma_idx_ = 0;
                algorithm_.encrypt(curr_ctr_, curr_gamma_);
                increment(curr_ctr_);
            }

            for (int j = 0; j < curr_block.size(); ++j) {
                curr_block[j] ^= curr_gamma_[curr_unused_gamma_idx_++];
            }

            std::copy(curr_block.begin(), curr_block.end(), dst.begin() + i);
        }
    }

    template<typename CipherType>
    void CTR<CipherType>::decrypt(const std::vector<uint8_t>& src, std::vector<uint8_t>& dst) {
        encrypt(src, dst);
    }


#endif //REFERENCEIMPLEMENTATIONS_CTR_H
