package com.amr.project.dao.abstracts;

import com.amr.project.model.entity.Discount;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DiscountRepository extends JpaRepository<Discount, Long> {
}
