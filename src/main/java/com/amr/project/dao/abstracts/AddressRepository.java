package com.amr.project.dao.abstracts;

import com.amr.project.model.entity.Address;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AddressRepository extends JpaRepository<Address, Long> {
}
